"""
CREDUENT-004 W3C DID Interoperability Module.
Translates Creduent agent:// URIs into W3C Decentralized Identifiers (did:creduent and did:web)
and converts agent.json identity documents into standard W3C DID Documents.
"""

from typing import Dict, Any, Optional, Union
import re


def agent_to_did(agent_id: str, method: str = "creduent", domain: Optional[str] = None) -> str:
    """
    Converts an agent:// URI into a W3C DID URI (did:creduent or did:web).

    Args:
        agent_id: The agent URI (e.g. 'agent://idevsec/steward')
        method: DID method, either 'creduent' or 'web'
        domain: Domain name required when method is 'web' (or inferred from namespace)

    Returns:
        W3C DID string (e.g. 'did:creduent:idevsec:steward' or 'did:web:idevsec.com:agent:steward')
    """
    if not agent_id.startswith("agent://"):
        raise ValueError(f"Invalid agent_id scheme: {agent_id}. Expected 'agent://...'")

    raw_path = agent_id[8:].strip("/")
    parts = raw_path.split("/")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError(f"Invalid agent_id format: {agent_id}. Expected 'agent://namespace/name'")

    namespace, name = parts[0], parts[1]

    if method == "creduent":
        return f"did:creduent:{namespace}:{name}"
    elif method == "web":
        target_domain = domain or f"{namespace}.com"
        # Sanitize domain for did:web format (colon replaces slashes)
        clean_domain = target_domain.replace("/", ":")
        return f"did:web:{clean_domain}:agent:{name}"
    else:
        raise ValueError(f"Unsupported DID method: '{method}'. Supported methods: 'creduent', 'web'")


def did_to_agent(did_uri: str) -> str:
    """
    Parses a did:creduent or did:web URI back into a Creduent agent:// URI.

    Args:
        did_uri: W3C DID string (e.g. 'did:creduent:idevsec:steward')

    Returns:
        Creduent agent:// URI string ('agent://idevsec/steward')
    """
    if did_uri.startswith("did:creduent:"):
        parts = did_uri[13:].split(":")
        if len(parts) >= 2:
            namespace, name = parts[0], parts[1]
            return f"agent://{namespace}/{name}"
        raise ValueError(f"Invalid did:creduent format: {did_uri}")

    elif did_uri.startswith("did:web:"):
        # Format: did:web:domain:agent:name
        parts = did_uri[8:].split(":")
        if len(parts) >= 3 and parts[-2] == "agent":
            name = parts[-1]
            domain = parts[0]
            namespace = domain.split(".")[0]
            return f"agent://{namespace}/{name}"
        elif len(parts) >= 2:
            # Fallback did:web parsing
            namespace = parts[0].split(".")[0]
            name = parts[-1]
            return f"agent://{namespace}/{name}"
        raise ValueError(f"Invalid did:web format: {did_uri}")

    raise ValueError(f"Unsupported DID scheme: {did_uri}. Expected 'did:creduent:' or 'did:web:'")


def agent_to_did_document(
    agent_data: Dict[str, Any], method: str = "creduent", domain: Optional[str] = None
) -> Dict[str, Any]:
    """
    Generates a standard W3C DID Document (JSON-LD) from a Creduent agent.json dictionary or record.

    Args:
        agent_data: Dictionary representing agent.json or attestation record
        method: DID method ('creduent' or 'web')
        domain: Domain name (optional)

    Returns:
        W3C DID Document dictionary
    """
    # Extract agent_id
    agent_id = agent_data.get("agent_id") or agent_data.get("identity", {}).get("agent_id")
    if not agent_id:
        raise ValueError("agent_data missing required 'agent_id' field")

    did_id = agent_to_did(agent_id, method=method, domain=domain)

    # Extract public key
    public_key = agent_data.get("public_key")
    if not public_key and "identity" in agent_data and "keys" in agent_data["identity"]:
        keys = agent_data["identity"]["keys"]
        if keys and len(keys) > 0:
            public_key = keys[0].get("public_key")

    key_id = f"{did_id}#key-1"
    endpoint = agent_data.get("endpoint") or agent_data.get("identity", {}).get("endpoint") or ""

    did_doc: Dict[str, Any] = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "id": did_id,
        "alsoKnownAs": [agent_id],
        "verificationMethod": [
            {
                "id": key_id,
                "type": "Ed25519VerificationKey2020",
                "controller": did_id,
                "publicKeyMultibase": public_key or ""
            }
        ],
        "authentication": [key_id],
        "assertionMethod": [key_id],
        "service": []
    }

    if endpoint:
        did_doc["service"].append({
            "id": f"{did_id}#endpoint",
            "type": "AgentServiceEndpoint",
            "serviceEndpoint": endpoint
        })

    return did_doc
