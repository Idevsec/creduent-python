import json
import requests
from dataclasses import dataclass
from typing import Optional

from creduent.exceptions import RegistrationError

@dataclass
class RegisterResult:
    """The result of registering an agent with the Creduent registry.

    Attributes:
        success (bool): Whether the registration was successful.
        attestation (Optional[dict]): The attestation metadata returned by the registry,
            or None if registration failed.
        error (Optional[str]): An error description if registration failed, else None.
    """
    success: bool  # True if registration succeeded, False otherwise.
    attestation: Optional[dict]  # Dictionary of attestation details.
    error: Optional[str] = None  # Error message description if success is False.

def register(
    agent_id: str,
    domain: str,
    agent_json_url: str,
    registry_url: str = "https://registry.idevsec.com"
) -> RegisterResult:
    """Register agent with Creduent registry.

    Args:
        agent_id (str): The unique identifier of the agent to register (e.g., "agent://...").
        domain (str): The domain name associated with the agent.
        agent_json_url (str): The URL pointing to the agent's well-known agent.json file.
        registry_url (str): The URL of the Creduent registry endpoint. Defaults to
            "https://registry.idevsec.com".

    Returns:
        RegisterResult: The result of the registration, containing success status,
            attestation dict, and any potential error message.

    Raises:
        RegistrationError: If the connection fails, registry returns invalid JSON,
            or a validation error occurs.
    """
    base_url = registry_url.rstrip('/')
    # If URL already ends with /registry, the endpoint is /register.
    # Otherwise, it's /registry/register.
    if base_url.endswith('/registry'):
        endpoint = f"{base_url}/register"
    else:
        endpoint = f"{base_url}/registry/register"
        
    payload = {
        "agent_id": agent_id,
        "domain": domain,
        "agent_json_url": agent_json_url
    }
    
    try:
        response = requests.post(
            endpoint,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
    except requests.RequestException as e:
        # If the preferred endpoint failed, try fallback /register directly
        if not base_url.endswith('/registry'):
            fallback_endpoint = f"{base_url}/register"
            try:
                response = requests.post(
                    fallback_endpoint,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=10
                )
            except requests.RequestException as inner_e:
                raise RegistrationError(f"Connection to Creduent registry failed: {inner_e}")
        else:
            raise RegistrationError(f"Connection to Creduent registry failed: {e}")
            
    if response.status_code == 200:
        try:
            attestation = response.json()
            return RegisterResult(success=True, attestation=attestation, error=None)
        except Exception as e:
            raise RegistrationError(f"Registry returned invalid JSON: {e}")
    else:
        # Non-200 error
        err_detail = response.text
        try:
            err_json = response.json()
            if isinstance(err_json, dict) and "detail" in err_json:
                err_detail = err_json["detail"]
        except Exception:
            pass
            
        raise RegistrationError(f"Registration failed with HTTP {response.status_code}: {err_detail}")
