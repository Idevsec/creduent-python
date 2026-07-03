from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import time
from urllib.parse import urlparse

from creduent.verify import verify, VerificationError, safe_requests_get
from creduent.sign import sign


class DiscoveryError(Exception):
    """Exception raised for discovery failures."""

    def __init__(self, message: str, detail: Optional[str] = None):
        super().__init__(message)
        self.detail = detail


@dataclass
class DiscoveryResult:
    """The result of discovering an agent's capabilities."""

    target_agent_id: str
    endpoint: str
    capabilities: List[Dict[str, Any] | str]
    authenticated: bool
    error: Optional[str] = None


def discover(
    target_agent_id: str,
    my_agent_id: Optional[str] = None,
    my_private_key: Optional[bytes] = None,
) -> DiscoveryResult:
    """
    Discover an agent's capabilities.

    If my_agent_id and my_private_key are provided, it performs a mutually
    authenticated handshake with the target agent's /discover endpoint to
    retrieve private, high-privilege capabilities.

    Args:
        target_agent_id (str): The URI of the target agent (e.g. "agent://idevsec/reconbot").
        my_agent_id (str, optional): The discovering agent's URI.
        my_private_key (bytes, optional): The discovering agent's private key PEM.

    Returns:
        DiscoveryResult: Contains the capabilities of the agent.
    """
    # 1. Verify the target agent to get its endpoint and public capabilities
    try:
        verify_result = verify(target_agent_id)
        if not verify_result.valid:
            return DiscoveryResult(
                target_agent_id=target_agent_id,
                endpoint="",
                capabilities=[],
                authenticated=False,
                error=f"Target agent verification failed: {verify_result.error}",
            )
    except VerificationError as e:
        return DiscoveryResult(
            target_agent_id=target_agent_id,
            endpoint="",
            capabilities=[],
            authenticated=False,
            error=f"Failed to fetch target agent identity: {str(e)}",
        )

    endpoint = verify_result.endpoint
    public_caps = verify_result.capabilities

    # 2. If no authentication is provided, or no endpoint exists, return public capabilities
    if not endpoint or not my_agent_id or not my_private_key:
        return DiscoveryResult(
            target_agent_id=verify_result.agent_id,
            endpoint=endpoint,
            capabilities=public_caps,
            authenticated=False,
        )

    # 3. Perform Authenticated Discovery
    # Construct the discovery payload
    payload = {
        "iss": my_agent_id,
        "aud": verify_result.agent_id,
        "exp": int(time.time()) + 60,  # 60 second expiry
        "action": "discover",
    }

    try:
        signed_payload = sign(payload, my_private_key)
    except Exception as e:
        return DiscoveryResult(
            target_agent_id=verify_result.agent_id,
            endpoint=endpoint,
            capabilities=public_caps,
            authenticated=False,
            error=f"Failed to sign discovery request: {str(e)}",
        )

    # Send POST request to the agent's /discover endpoint
    import requests

    discover_url = endpoint.rstrip("/") + "/discover"

    try:
        allow_private = "localhost" in discover_url or "127.0.0.1" in discover_url
        if allow_private:
            response = requests.post(discover_url, json=signed_payload, timeout=5)
        else:
            response = requests.post(discover_url, json=signed_payload, timeout=5)

        if response.status_code == 200:
            data = response.json()
            # Merge public capabilities with the newly discovered private ones, preventing exact duplicates
            private_caps = data.get("capabilities", [])
            merged = list(public_caps)
            for cap in private_caps:
                if cap not in merged:
                    merged.append(cap)

            return DiscoveryResult(
                target_agent_id=verify_result.agent_id,
                endpoint=endpoint,
                capabilities=merged,
                authenticated=True,
            )
        else:
            # Fall back to public capabilities
            return DiscoveryResult(
                target_agent_id=verify_result.agent_id,
                endpoint=endpoint,
                capabilities=public_caps,
                authenticated=False,
                error=f"Authenticated discovery failed with HTTP {response.status_code}",
            )

    except requests.RequestException as e:
        # Network error: fall back to public capabilities
        return DiscoveryResult(
            target_agent_id=verify_result.agent_id,
            endpoint=endpoint,
            capabilities=public_caps,
            authenticated=False,
            error=f"Network error during authenticated discovery: {str(e)}",
        )
