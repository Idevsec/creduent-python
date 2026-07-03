import json
import base64
import requests
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from creduent.crypto import canonicalize
from creduent.exceptions import CreduentError


@dataclass
class RenewResult:
    """The result of renewing an agent's attestation.

    Attributes:
        success (bool): Whether the renewal was successful.
        attestation (Optional[dict]): The renewed attestation record, or None if failed.
        error (Optional[str]): An error description if renewal failed, else None.
    """

    success: bool
    attestation: Optional[dict]
    error: Optional[str] = None


def renew(
    agent_id: str,
    new_expires_at: str,
    private_key_pem: str,
    registry_url: str = "https://creduent.idevsec.com",
) -> RenewResult:
    """Renew an agent's attestation validity period.

    Args:
        agent_id (str): The agent's URI.
        new_expires_at (str): The new expiration timestamp in ISO format.
        private_key_pem (str): The agent's private key in PEM format.
        registry_url (str): The registry URL. Defaults to "https://creduent.idevsec.com".

    Returns:
        RenewResult: The result of the renewal.
    """
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"), password=None
        )
        if not isinstance(private_key, ed25519.Ed25519PrivateKey):
            raise ValueError("Key is not an Ed25519 private key")
    except Exception as e:
        raise CreduentError(f"Failed parsing private key PEM: {e}")

    payload = {"agent_id": agent_id, "new_expires_at": new_expires_at}

    try:
        canonical_str = canonicalize(payload)
        canonical_bytes = canonical_str.encode("utf-8")
        signature_bytes = private_key.sign(canonical_bytes)
        signature = base64.b64encode(signature_bytes).decode("utf-8")
    except Exception as e:
        raise CreduentError(f"Failed to sign renewal payload: {e}")

    base_url = registry_url.rstrip("/")
    if base_url.endswith("/registry"):
        endpoint = f"{base_url}/renew"
    else:
        endpoint = f"{base_url}/registry/renew"

    req_payload = {
        "agent_id": agent_id,
        "new_expires_at": new_expires_at,
        "signature": signature,
    }

    try:
        response = requests.post(
            endpoint,
            json=req_payload,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
    except requests.RequestException as e:
        raise CreduentError(f"Connection to Creduent registry failed: {e}")

    if response.status_code == 200:
        try:
            attestation = response.json()
            return RenewResult(success=True, attestation=attestation, error=None)
        except Exception as e:
            raise CreduentError(f"Registry returned invalid JSON: {e}")
    else:
        err_detail = response.text
        try:
            err_json = response.json()
            if isinstance(err_json, dict) and "detail" in err_json:
                err_detail = err_json["detail"]
        except Exception:
            pass
        return RenewResult(
            success=False,
            attestation=None,
            error=f"Renewal failed with HTTP {response.status_code}: {err_detail}",
        )
