from dataclasses import dataclass
from typing import Optional

from creduent.utils import safe_requests_get
from creduent.exceptions import AttestationError

@dataclass
class AttestResult:
    """The result of an agent attestation query.

    Attributes:
        attested (bool): True if the agent is actively attested, False if not
            attested or if the attestation has expired.
        level (Optional[str]): The level of attestation (e.g., "verified").
        issued_at (Optional[str]): The ISO-8601 timestamp when the attestation was issued.
        expires_at (Optional[str]): The ISO-8601 timestamp when the attestation expires.
        error (Optional[str]): An error description if attestation failed or expired.
    """
    attested: bool
    level: Optional[str]
    issued_at: Optional[str]
    expires_at: Optional[str]
    error: Optional[str] = None

def attest(
    agent_id: str,
    registry_url: str = "https://api.idevsec.com"
) -> AttestResult:
    """Fetch attestation for an agent from the Creduent registry.

    Args:
        agent_id (str): The identifier of the agent to query (e.g., "agent://...").
        registry_url (str): The base URL of the Creduent registry. Defaults to
            "https://api.idevsec.com".

    Returns:
        AttestResult: The attestation result. If the registry data indicates the
            agent's attestation is expired (the `expired` flag is True or status
            is "expired"), returns `AttestResult` with `attested=False` and an
            appropriate error message.

    Raises:
        AttestationError: If the connection to the registry fails, the registry
            returns invalid JSON, or a non-404 HTTP error occurs.
    """
    base_url = registry_url.rstrip('/')
    
    # URL escape agent_id if needed, but since it's a path parameter:
    # FastAPI path parameter matches `/attest/{agent_id:path}`
    # E.g. /registry/attest/agent://creduent/reconbot
    # Note: double slashes in agent:// might get collapsed by some proxies or routers.
    # The registry endpoint router handles path normalization.
    if base_url.endswith('/registry'):
        endpoint = f"{base_url}/attest/{agent_id}"
    else:
        endpoint = f"{base_url}/registry/attest/{agent_id}"
        
    try:
        response = safe_requests_get(endpoint, timeout=10)
    except Exception as e:
        # Fallback without /registry if default failed
        if not base_url.endswith('/registry'):
            fallback_endpoint = f"{base_url}/attest/{agent_id}"
            try:
                response = safe_requests_get(fallback_endpoint, timeout=10)
            except Exception as inner_e:
                raise AttestationError(f"Connection to Creduent registry failed: {inner_e}")
        else:
            raise AttestationError(f"Connection to Creduent registry failed: {e}")
            
    if response.status_code == 200:
        try:
            data = response.json()
            if data.get("expired") is True or data.get("status") == "expired":
                return AttestResult(
                    attested=False,
                    level=data.get("level"),
                    issued_at=data.get("issued_at"),
                    expires_at=data.get("expires_at"),
                    error="Attestation has expired. Please renew."
                )
            return AttestResult(
                attested=True,
                level=data.get("level", "verified"),
                issued_at=data.get("issued_at"),
                expires_at=data.get("expires_at"),
                error=None
            )
        except Exception as e:
            raise AttestationError(f"Registry returned invalid JSON: {e}")

    elif response.status_code == 404:
        # Agent is not registered/attested
        return AttestResult(
            attested=False,
            level=None,
            issued_at=None,
            expires_at=None,
            error="Attestation not found or expired"
        )
    else:
        # Server or validation error
        err_detail = response.text
        try:
            err_json = response.json()
            if isinstance(err_json, dict) and "detail" in err_json:
                err_detail = err_json["detail"]
        except Exception:
            pass
            
        raise AttestationError(f"Attestation query failed with HTTP {response.status_code}: {err_detail}")
