import logging
from typing import Any, Dict, Optional

from creduent.verify import verify
from creduent.exceptions import VerificationError

logger = logging.getLogger(__name__)


class CreduentGoogleADKPlugin:
    """Google Agent Development Kit (ADK) execution interceptor for Creduent Zero-Trust Verification."""

    def __init__(self, strict: bool = True):
        self.strict = strict

    def verify_agent(self, agent_uri: str) -> Dict[str, Any]:
        """
        Intercepts Google ADK agent execution and verifies the agent attestation payload.

        Args:
            agent_uri: The target Creduent agent URI (e.g. agent://namespace/name)
        """
        logger.info(f"[CreduentGoogleADKPlugin] Verifying agent URI: {agent_uri}")
        try:
            result = verify(agent_uri)
            if result.valid:
                return {
                    "status": "SUCCESS",
                    "agent_uri": agent_uri,
                    "verified": True,
                    "attestations": getattr(result, "attestations", []),
                }
            else:
                error_msg = f"ADK Verification failed for {agent_uri}: {result.error}"
                logger.warning(error_msg)
                if self.strict:
                    raise VerificationError(error_msg)
                return {"status": "FAILED", "agent_uri": agent_uri, "verified": False, "error": error_msg}
        except Exception as e:
            error_msg = f"ADK verification execution error: {str(e)}"
            logger.error(error_msg)
            if self.strict and not isinstance(e, VerificationError):
                raise VerificationError(error_msg) from e
            elif self.strict:
                raise
            return {"status": "FAILED", "agent_uri": agent_uri, "verified": False, "error": error_msg}
