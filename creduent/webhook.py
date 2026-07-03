import json
import base64
import requests
import urllib.parse
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from creduent.crypto import canonicalize
from creduent.exceptions import CreduentError


@dataclass
class WebhookResult:
    """The result of a webhook operation.

    Attributes:
        success (bool): Whether the operation was successful.
        agent_id (Optional[str]): The agent's URI.
        webhook_url (Optional[str]): The registered webhook URL.
        error (Optional[str]): Error description if operation failed.
    """

    success: bool
    agent_id: Optional[str] = None
    webhook_url: Optional[str] = None
    error: Optional[str] = None


def register_webhook(
    agent_id: str,
    webhook_url: str,
    private_key_pem: str,
    registry_url: str = "https://creduent.idevsec.com",
) -> WebhookResult:
    """Register a webhook URL for an agent.

    Args:
        agent_id (str): The agent's URI.
        webhook_url (str): The webhook URL to receive protocol updates.
        private_key_pem (str): The agent's private key in PEM format.
        registry_url (str): The registry URL. Defaults to "https://creduent.idevsec.com".

    Returns:
        WebhookResult: The result of registration.
    """
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"), password=None
        )
        if not isinstance(private_key, ed25519.Ed25519PrivateKey):
            raise ValueError("Key is not an Ed25519 private key")
    except Exception as e:
        raise CreduentError(f"Failed parsing private key PEM: {e}")

    payload = {"agent_id": agent_id, "webhook_url": webhook_url}

    try:
        canonical_str = canonicalize(payload)
        canonical_bytes = canonical_str.encode("utf-8")
        signature_bytes = private_key.sign(canonical_bytes)
        signature = base64.b64encode(signature_bytes).decode("utf-8")
    except Exception as e:
        raise CreduentError(f"Failed to sign webhook payload: {e}")

    base_url = registry_url.rstrip("/")
    if base_url.endswith("/registry"):
        endpoint = f"{base_url}/webhook/register"
    else:
        endpoint = f"{base_url}/registry/webhook/register"

    req_payload = {
        "agent_id": agent_id,
        "webhook_url": webhook_url,
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
            data = response.json()
            return WebhookResult(
                success=True,
                agent_id=data.get("agent_id", agent_id),
                webhook_url=data.get("webhook_url", webhook_url),
                error=None,
            )
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
        return WebhookResult(
            success=False,
            error=f"Webhook registration failed with HTTP {response.status_code}: {err_detail}",
        )


def query_webhook(
    agent_id: str, registry_url: str = "https://creduent.idevsec.com"
) -> WebhookResult:
    """Query the registered webhook URL for an agent.

    Args:
        agent_id (str): The agent's URI.
        registry_url (str): The registry URL. Defaults to "https://creduent.idevsec.com".

    Returns:
        WebhookResult: The result of query.
    """
    base_url = registry_url.rstrip("/")
    encoded_agent_id = urllib.parse.quote(agent_id, safe="")
    if base_url.endswith("/registry"):
        endpoint = f"{base_url}/webhook/{encoded_agent_id}"
    else:
        endpoint = f"{base_url}/registry/webhook/{encoded_agent_id}"

    try:
        response = requests.get(
            endpoint, headers={"Content-Type": "application/json"}, timeout=10
        )
    except requests.RequestException as e:
        raise CreduentError(f"Connection to Creduent registry failed: {e}")

    if response.status_code == 200:
        try:
            data = response.json()
            return WebhookResult(
                success=True,
                agent_id=data.get("agent_id", agent_id),
                webhook_url=data.get("webhook_url"),
                error=None,
            )
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
        return WebhookResult(
            success=False,
            error=f"Webhook query failed with HTTP {response.status_code}: {err_detail}",
        )
