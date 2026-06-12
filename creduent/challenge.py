import base64
import hashlib
import json
import urllib.parse
from typing import Optional
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from creduent.utils import safe_requests_get, safe_requests_post
from creduent.exceptions import CreduentError, VerificationError
from creduent.crypto import canonicalize
from creduent.attest import attest

def create_proof(
    agent_id: str,
    private_key_pem: str,
    registry_url: str = "https://registry.idevsec.com"
) -> dict:
    """Creates a signed challenge proof for the agent.

    1. Fetches a challenge from GET /challenge/{agent_id}
    2. Signs (challenge + nonce) using agent's private key
    3. Calls POST /verify-challenge with the signature and nonce
    4. Returns the response token containing the proof_token

    Args:
        agent_id: The agent ID (e.g. agent://cyberhavox/havox-ai)
        private_key_pem: The private key PEM string of the agent
        registry_url: The registry base URL

    Returns:
        dict: The response containing proof_token, verified status, etc.

    Raises:
        CreduentError: If any step of the challenge-response flow fails.
    """
    base_url = registry_url.rstrip('/')
    escaped_agent_id = urllib.parse.quote(agent_id, safe='')
    
    # URL construction
    if base_url.endswith('/registry'):
        challenge_url = f"{base_url}/challenge/{escaped_agent_id}"
        verify_url = f"{base_url}/verify-challenge"
    else:
        challenge_url = f"{base_url}/registry/challenge/{escaped_agent_id}"
        verify_url = f"{base_url}/registry/verify-challenge"

    # Step 1: Fetch challenge
    try:
        response = safe_requests_get(challenge_url, timeout=10)
    except Exception as e:
        # Fallback if without /registry default failed
        if not base_url.endswith('/registry'):
            fallback_url = f"{base_url}/challenge/{escaped_agent_id}"
            try:
                response = safe_requests_get(fallback_url, timeout=10)
                verify_url = f"{base_url}/verify-challenge"
            except Exception as inner_e:
                raise CreduentError(f"Connection to Creduent registry failed: {inner_e}")
        else:
            raise CreduentError(f"Connection to Creduent registry failed: {e}")

    if response.status_code != 200:
        err_msg = response.text
        try:
            err_json = response.json()
            if isinstance(err_json, dict) and "detail" in err_json:
                err_msg = err_json["detail"]
        except Exception:
            pass
        raise CreduentError(f"Failed to fetch challenge: HTTP {response.status_code} - {err_msg}")

    try:
        challenge_data = response.json()
    except Exception as e:
        raise CreduentError(f"Registry returned invalid JSON for challenge: {e}")

    challenge = challenge_data.get("challenge")
    nonce = challenge_data.get("nonce")
    if not challenge or not nonce:
        raise CreduentError("Registry challenge response missing required fields")

    # Step 2: Sign (challenge + nonce) using agent's private key
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=None
        )
        if not isinstance(private_key, ed25519.Ed25519PrivateKey):
            raise ValueError("Key is not an Ed25519 private key")
    except Exception as e:
        raise CreduentError(f"Failed parsing private key PEM: {e}")

    try:
        message_str = challenge + nonce
        hashed_bytes = hashlib.sha256(message_str.encode('utf-8')).digest()
        signature_bytes = private_key.sign(hashed_bytes)
        signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')
    except Exception as e:
        raise CreduentError(f"Failed to sign challenge: {e}")

    # Step 3: Call POST /verify-challenge
    payload = {
        "agent_id": agent_id,
        "nonce": nonce,
        "signature": signature_b64
    }

    try:
        verify_response = safe_requests_post(verify_url, json=payload, timeout=10)
    except Exception as e:
        raise CreduentError(f"Connection to Creduent registry for verify failed: {e}")

    if verify_response.status_code != 200:
        err_msg = verify_response.text
        try:
            err_json = verify_response.json()
            if isinstance(err_json, dict) and "detail" in err_json:
                err_msg = err_json["detail"]
        except Exception:
            pass
        raise CreduentError(f"Challenge verification failed: HTTP {verify_response.status_code} - {err_msg}")

    try:
        return verify_response.json()
    except Exception as e:
        raise CreduentError(f"Registry returned invalid JSON for verification response: {e}")

def verify_proof(
    proof_token: str,
    agent_id: str,
    registry_url: str = "https://registry.idevsec.com",
    registry_pubkey: Optional[str] = None
) -> bool:
    """Verifies a signed challenge proof token.

    1. Decodes and parses the proof_token payload
    2. Fetches the agent's attestation status to verify they are active/registered
    3. Identifies the registry's public key (pinned argument, environment variable, or dynamic fallback)
    4. Verifies the proof token signature using the registry's public key
    5. Checks validity timestamp

    Args:
        proof_token: The base64-encoded signed proof token string
        agent_id: The agent ID (e.g. agent://cyberhavox/havox-ai)
        registry_url: The registry base URL
        registry_pubkey: The expected registry public key (optional pinning)

    Returns:
        bool: True if signature and token are valid, False otherwise
    """
    # Step 1: Decode proof_token
    try:
        decoded_bytes = base64.b64decode(proof_token)
        proof_obj = json.loads(decoded_bytes.decode('utf-8'))
    except Exception:
        return False

    token_agent_id = proof_obj.get("agent_id")
    verified = proof_obj.get("verified")
    level = proof_obj.get("level")
    valid_until_str = proof_obj.get("valid_until")
    signature_b64 = proof_obj.get("signature")

    if not token_agent_id or not verified or not valid_until_str or not signature_b64:
        return False

    # Normalize agent_id for comparison
    norm_agent_id = agent_id
    if norm_agent_id.startswith("agent:/") and not norm_agent_id.startswith("agent://"):
        norm_agent_id = "agent://" + norm_agent_id[7:]
    
    norm_token_agent_id = token_agent_id
    if norm_token_agent_id.startswith("agent:/") and not norm_token_agent_id.startswith("agent://"):
        norm_token_agent_id = "agent://" + norm_token_agent_id[7:]

    if norm_token_agent_id != norm_agent_id:
        return False

    # Step 2: Fetch agent attestation to confirm they are active/registered
    try:
        attest_result = attest(agent_id, registry_url)
        if not attest_result.attested:
            return False
    except Exception:
        return False

    # Step 3: Check valid_until has not expired
    try:
        valid_until = datetime.fromisoformat(valid_until_str.replace("Z", "+00:00"))
        if datetime.now(timezone.utc) > valid_until:
            return False
    except Exception:
        return False

    # Step 4: Determine registry public key
    pubkey_str = registry_pubkey
    if not pubkey_str:
        import os
        pubkey_str = os.environ.get("CREDUENT_REGISTRY_PUBKEY")

    if not pubkey_str:
        # Fallback to fetching dynamically
        base_url = registry_url.rstrip('/')
        if base_url.endswith('/registry'):
            pubkey_url = f"{base_url}/public-key"
        else:
            pubkey_url = f"{base_url}/registry/public-key"

        try:
            pub_response = safe_requests_get(pubkey_url, timeout=10)
            if pub_response.status_code != 200:
                if not base_url.endswith('/registry'):
                    fallback_pubkey_url = f"{base_url}/public-key"
                    pub_response = safe_requests_get(fallback_pubkey_url, timeout=10)
        except Exception:
            return False

        if pub_response.status_code != 200:
            return False

        try:
            pub_data = pub_response.json()
            pubkey_str = pub_data.get("public_key", "")
        except Exception:
            return False

    if not pubkey_str or not pubkey_str.startswith("ed25519:"):
        return False

    # Step 5: Verify signature using registry public key
    try:
        pubkey_b64 = pubkey_str.split(":", 1)[1]
        pubkey_bytes = base64.b64decode(pubkey_b64)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(pubkey_bytes)
        
        signature_bytes = base64.b64decode(signature_b64)

        # Construct signed payload (without signature field)
        proof_copy = proof_obj.copy()
        proof_copy.pop("signature", None)
        canonical_str = canonicalize(proof_copy)
        canonical_bytes = canonical_str.encode('utf-8')

        public_key.verify(signature_bytes, canonical_bytes)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False
