import logging
from typing import Any, Dict

from creduent.verify import verify
from creduent.exceptions import VerificationError

logger = logging.getLogger(__name__)


def verify_agent_node(state: Dict[str, Any], strict: bool = True) -> Dict[str, Any]:
    """
    A LangGraph node function that verifies a Creduent agent URI.
    It expects the state dictionary to contain an 'agent_uri' key.
    It returns an updated state with 'verification_result'.

    In strict mode (default), it raises a VerificationError on failure.
    """
    agent_uri = state.get("agent_uri")
    if not agent_uri:
        if strict:
            raise VerificationError("No 'agent_uri' found in state.")
        return {"verification_result": {"verified": False, "error": "No URI provided"}}

    logger.info(f"LangGraph node verifying agent: {agent_uri}")
    try:
        result = verify(agent_uri)
        result_dict = {
            "verified": result.valid,
            "agent_id": result.agent_id,
            "public_key": result.public_key,
            "endpoint": result.endpoint,
            "capabilities": result.capabilities,
            "error": result.error,
        }

        if result.valid:
            return {"verification_result": result_dict}
        else:
            error_msg = f"Verification failed for {agent_uri}: {result.error}"
            logger.warning(error_msg)
            if strict:
                raise VerificationError(error_msg)
            return {"verification_result": result_dict}
    except Exception as e:
        error_msg = f"Verification process failed: {str(e)}"
        logger.error(error_msg)
        if strict and not isinstance(e, VerificationError):
            raise VerificationError(error_msg) from e
        elif strict:
            raise
        return {"verification_result": {"verified": False, "error": str(e)}}
