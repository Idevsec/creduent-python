import os
import sys
import json
import base64
import argparse
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import List, Optional
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

from creduent.crypto import canonicalize
from creduent.utils import safe_requests_get
from creduent.exceptions import VerificationError


@dataclass
class VerifyResult:
    """Represents the results of verifying an agent's identity and signature.

    Attributes:
        valid (bool): Whether the verification was successful.
        agent_id (str): The identifier of the verified agent.
        public_key (str): The public key of the agent.
        endpoint (str): The endpoint where the agent is hosted.
        capabilities (List[str]): The list of capabilities supported by the agent.
        error (Optional[str]): The error message if verification failed, else None.
    """

    valid: bool  # True if the verification succeeded, False otherwise.
    agent_id: str  # The unique identifier of the agent.
    public_key: str  # The public key of the agent in 'ed25519:<base64>' format.
    endpoint: str  # The service endpoint URL of the agent.
    capabilities: List[str]  # The list of capabilities advertised by the agent.
    error: Optional[str] = None  # Error message description if valid is False.


def resolve_target(target: str) -> str:
    """Resolves a target identifier to a fetchable well-known agent.json URL.

    Args:
        target (str): The target identifier to resolve. Can be one of three formats:
            1. HTTP/HTTPS URL: A direct URL pointing to an agent's endpoint or
               well-known path (e.g., "https://example.com" or
               "https://example.com/.well-known/agent.json").
            2. agent:// URI: A protocol URI pointing to a specific agent path
               (e.g., "agent://idevsec/steward" or "agent://domain/path").
            3. Domain or hostname: A standard domain name string (e.g., "creduent.idevsec.com").

    Returns:
        str: The resolved HTTPS/HTTP URL pointing to the agent's
            well-known agent.json file (e.g., "https://example.com/.well-known/agent.json").

    Raises:
        None
    """
    target = target.strip()

    # 1. Handle HTTP/HTTPS URLs
    if target.startswith("http://") or target.startswith("https://"):
        from urllib.parse import urlparse, urlunparse

        parsed = urlparse(target)
        if not parsed.path.endswith("/.well-known/agent.json"):
            # Append well-known path if not present
            path = parsed.path.rstrip("/") + "/.well-known/agent.json"
            return urlunparse(
                (
                    parsed.scheme,
                    parsed.netloc,
                    path,
                    parsed.params,
                    parsed.query,
                    parsed.fragment,
                )
            )
        return target

    # 2. Handle agent:// URIs
    if target.startswith("agent://"):
        from urllib.parse import urlparse

        parsed = urlparse(target)
        namespace = parsed.netloc

        # Default mapping fallback for testing/steward
        if target == "agent://idevsec/steward":
            return "https://creduent.idevsec.com/.well-known/agent.json"

        # Try to resolve domain from Creduent registry
        try:
            registry_url = "https://creduent.idevsec.com/registry/attest/" + target
            response = safe_requests_get(registry_url, timeout=5)
            if response.status_code == 200:
                attestation = response.json()
                domain = attestation.get("domain")
                if domain:
                    return f"https://{domain}/.well-known/agent.json"
        except Exception:
            pass

        # Fallback to default namespace resolution
        return f"https://api.{namespace}.ai/.well-known/agent.json"

    # 3. Handle domain or host name (e.g. "creduent.idevsec.com")
    scheme = "http" if "localhost" in target or "127.0.0.1" in target else "https"
    return f"{scheme}://{target}/.well-known/agent.json"


def verify(target: str | dict) -> VerifyResult:
    """Verify a self-signed agent.json from a string target or a dictionary.

    Args:
        target (str | dict): The target to verify. Valid input types include:
            - str: A domain name, an HTTP/HTTPS URL, an agent:// URI, or a path
              to a local JSON file.
            - dict: A pre-loaded dictionary representation of an agent.json document.

    Returns:
        VerifyResult: The result of the verification, indicating whether the
            signature and schema are valid, along with agent metadata.

    Raises:
        VerificationError: If connection or critical target resolution fails.
    """
    doc = None
    if isinstance(target, dict):
        doc = target
    elif isinstance(target, str):
        resolved_url = resolve_target(target)
        try:
            allow_private = "localhost" in resolved_url or "127.0.0.1" in resolved_url
            response = safe_requests_get(
                resolved_url, timeout=5, allow_private=allow_private
            )
            if response.status_code != 200:
                raise VerificationError(
                    f"Failed to fetch agent.json: HTTP status {response.status_code}"
                )
            doc = response.json()
        except Exception as e:
            # Re-raise VerificationError or wrap other errors
            if isinstance(e, VerificationError):
                raise
            err_msg = str(e)
            if hasattr(e, "detail"):
                err_msg = e.detail
            raise VerificationError(f"Failed to retrieve agent.json: {err_msg}")
    else:
        raise VerificationError("Target must be a dictionary or a string")

    if not isinstance(doc, dict):
        return VerifyResult(
            valid=False,
            agent_id="",
            public_key="",
            endpoint="",
            capabilities=[],
            error="Parsed document is not a JSON object",
        )

    version = doc.get("version", "1.0")
    if version not in ["1.0", "1.1", "2.0"]:
        return VerifyResult(
            valid=False,
            agent_id="",
            public_key="",
            endpoint="",
            capabilities=[],
            error=f"Unsupported protocol version: {version}",
        )

    # Extract fields based on schema version
    if version == "2.0":
        identity = doc.get("identity", {})
        policy = doc.get("policy", {})

        if not isinstance(identity, dict) or not isinstance(policy, dict):
            return VerifyResult(
                valid=False,
                agent_id="",
                public_key="",
                endpoint="",
                capabilities=[],
                error="v2.0 agent document must contain identity and policy objects",
            )

        agent_id = identity.get("agent_id", "")
        endpoint = identity.get("endpoint", "")
        capabilities = policy.get("capabilities", [])
        keys = identity.get("keys", [])

        # Verify required inner fields exist
        required_identity = ["agent_id", "owner", "keys", "endpoint"]
        for field in required_identity:
            if field not in identity:
                return VerifyResult(
                    valid=False,
                    agent_id=agent_id,
                    public_key="",
                    endpoint=endpoint,
                    capabilities=capabilities,
                    error=f"Missing required field 'identity.{field}' in v2.0 agent.json",
                )
        if "capabilities" not in policy:
            return VerifyResult(
                valid=False,
                agent_id=agent_id,
                public_key="",
                endpoint=endpoint,
                capabilities=capabilities,
                error="Missing required field 'policy.capabilities' in v2.0 agent.json",
            )
        if "signature" not in doc:
            return VerifyResult(
                valid=False,
                agent_id=agent_id,
                public_key="",
                endpoint=endpoint,
                capabilities=capabilities,
                error="Missing required field 'signature' in v2.0 agent.json",
            )
    else:
        agent_id = doc.get("agent_id", "")
        endpoint = doc.get("endpoint", "")
        capabilities = doc.get("capabilities", [])

        # Extract keys array or fallback to legacy public_key
        keys = doc.get("keys", [])
        if not keys and "public_key" in doc:
            keys = [
                {
                    "id": "legacy",
                    "type": "ed25519",
                    "public_key": doc.get("public_key"),
                    "status": "active",
                }
            ]

        required_v1 = [
            "version",
            "agent_id",
            "owner",
            "endpoint",
            "capabilities",
            "signature",
        ]
        for field in required_v1:
            if field not in doc:
                return VerifyResult(
                    valid=False,
                    agent_id=agent_id,
                    public_key="",
                    endpoint=endpoint,
                    capabilities=capabilities,
                    error=f"Missing required field '{field}' in agent.json",
                )

    if isinstance(target, str) and target.startswith("agent://"):
        if agent_id != target:
            return VerifyResult(
                valid=False,
                agent_id=agent_id,
                public_key="",
                endpoint=endpoint,
                capabilities=capabilities,
                error=f"Cross-Namespace Spoofing Detected: Document claims agent_id '{agent_id}' but target was '{target}'",
            )

    # We will use the first active key we find as the primary 'public_key' for the VerifyResult,
    # but we will try validating against all active keys.
    primary_public_key_str = ""
    if keys and isinstance(keys, list):
        for k in keys:
            if isinstance(k, dict) and k.get("status") == "active":
                primary_public_key_str = k.get("public_key", "")
                break

    if not isinstance(capabilities, list):
        return VerifyResult(
            valid=False,
            agent_id=agent_id,
            public_key=primary_public_key_str,
            endpoint=endpoint,
            capabilities=[],
            error="Capabilities field must be a list of strings",
        )

    if not isinstance(keys, list) or len(keys) == 0:
        return VerifyResult(
            valid=False,
            agent_id=agent_id,
            public_key=primary_public_key_str,
            endpoint=endpoint,
            capabilities=capabilities,
            error="No keys found in agent.json (missing 'keys' array and legacy 'public_key')",
        )

    # 2. Cryptographic signature check
    signature_b64 = doc.get("signature")
    try:
        signature_bytes = base64.b64decode(signature_b64)
    except Exception:
        return VerifyResult(
            valid=False,
            agent_id=agent_id,
            public_key=primary_public_key_str,
            endpoint=endpoint,
            capabilities=capabilities,
            error="Signature is not valid base64.",
        )

    # Clone doc and remove signature before canonicalizing
    doc_copy = doc.copy()
    doc_copy.pop("signature", None)

    try:
        canonical_str = canonicalize(doc_copy)
        canonical_bytes = canonical_str.encode("utf-8")
    except Exception as e:
        return VerifyResult(
            valid=False,
            agent_id=agent_id,
            public_key=primary_public_key_str,
            endpoint=endpoint,
            capabilities=capabilities,
            error=f"Failed to canonicalize document: {e}",
        )

    now = datetime.now(timezone.utc)
    validation_error = "No active valid keys found."

    for key_entry in keys:
        if not isinstance(key_entry, dict):
            continue

        if key_entry.get("status") != "active":
            continue

        expires_at_str = key_entry.get("expires_at")
        if expires_at_str:
            try:
                # Handle ISO format strings like "2027-01-01T00:00:00Z"
                if expires_at_str.endswith("Z"):
                    expires_at_str = expires_at_str[:-1] + "+00:00"
                expires_at = datetime.fromisoformat(expires_at_str)
                if expires_at < now:
                    validation_error = "Active key is expired."
                    continue
            except ValueError:
                # If we can't parse the expiry, we should treat the key as invalid for safety
                validation_error = "Invalid expires_at format."
                continue

        pub_key_str = key_entry.get("public_key", "")
        if not pub_key_str.startswith("ed25519:"):
            validation_error = (
                "Unsupported public key format. Only 'ed25519:' prefix is supported."
            )
            continue

        try:
            pk_b64 = pub_key_str.split(":", 1)[1]
            public_key_bytes = base64.b64decode(pk_b64)
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)

            # Verify signature
            public_key.verify(signature_bytes, canonical_bytes)

            # If we get here, verification succeeded with this key!
            return VerifyResult(
                valid=True,
                agent_id=agent_id,
                public_key=pub_key_str,
                endpoint=endpoint,
                capabilities=capabilities,
                error=None,
            )

        except InvalidSignature:
            validation_error = (
                "Cryptographic signature in agent.json is INVALID for the tested key."
            )
        except Exception as e:
            validation_error = f"Signature verification failed: {e}"

    # If we exit the loop, no active key validated the signature
    return VerifyResult(
        valid=False,
        agent_id=agent_id,
        public_key=primary_public_key_str,
        endpoint=endpoint,
        capabilities=capabilities,
        error=validation_error,
    )


def print_help() -> None:
    """Print a styled help message for the verification CLI."""
    print("""
\033[1m\033[36m* CREDUENT VERIFY CLI\033[0m \033[90m-\033[0m \033[1m\033[37mAI Agent Identity Verification Utility\033[0m
\033[90mVersion 0.4.0 | Developed by IDevSec

PyPI  : https://pypi.org/project/creduent/
GitHub: https://github.com/idevsec/creduent\033[0m

\033[1m\033[32mUSAGE:\033[0m
  $ \033[1mcreduent-verify\033[0m \033[33m<target>\033[0m

\033[1m\033[36mARGUMENTS:\033[0m
  \033[1mtarget\033[0m                \033[90mVerification target (domain, URL, agent:// URI, or local JSON path)\033[0m

\033[1m\033[33mEXAMPLES:\033[0m
  \033[90m# Verify a local file\033[0m
  $ \033[1mcreduent-verify agent.json\033[0m

  \033[90m# Verify by URL\033[0m
  $ \033[1mcreduent-verify https://yourdomain.com/.well-known/agent.json\033[0m

  \033[90m# Verify by domain\033[0m
  $ \033[1mcreduent-verify yourdomain.com\033[0m

  \033[90m# Verify by agent:// URI\033[0m
  $ \033[1mcreduent-verify agent://idevsec/steward\033[0m
  """)


def main() -> None:
    """CLI entry point for the Creduent verification tool.

    Args:
        None

    Returns:
        None

    Raises:
        SystemExit: Exits with status 0 on successful verification, or 1 on failure.
    """
    if len(sys.argv) < 2 or "-h" in sys.argv or "--help" in sys.argv:
        print_help()
        sys.exit(0)

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("target")

    try:
        args = parser.parse_args()
    except SystemExit:
        print_help()
        sys.exit(1)

    target = args.target
    # Check if target is a local file path
    if os.path.exists(target):
        try:
            with open(target, "r", encoding="utf-8") as f:
                target = json.load(f)
        except Exception as e:
            print(f"[-] Error reading local target file: {e}", file=sys.stderr)
            sys.exit(1)

    try:
        result = verify(target)
        if result.valid:
            print("\n" + "=" * 50)
            print("[SUCCESS] IDENTITY VERIFIED & CRYPTOGRAPHICALLY VALID")
            print(f"Agent ID:     {result.agent_id}")
            print(f"Public Key:   {result.public_key}")
            print(f"Endpoint:     {result.endpoint}")
            print(f"Capabilities: {', '.join(result.capabilities)}")
            print("=" * 50)
            sys.exit(0)
        else:
            print("\n" + "=" * 50)
            print("[FAILED] VERIFICATION FAILED")
            print(f"Error: {result.error}")
            print("=" * 50)
            sys.exit(1)
    except Exception as e:
        print(f"[-] Error during verification pipeline: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
