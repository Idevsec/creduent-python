import logging
from typing import Any, Dict

try:
    from crewai.tools import BaseTool
    from pydantic import BaseModel, Field
    HAS_CREWAI = True
except ImportError:
    HAS_CREWAI = False
    class BaseTool: pass
    class BaseModel: pass
    def Field(*args, **kwargs): return None

from creduent.verify import verify
from creduent.exceptions import VerificationError

logger = logging.getLogger(__name__)

if HAS_CREWAI:
    class CreduentVerifyInput(BaseModel):
        agent_uri: str = Field(..., description="The Creduent URI of the agent to verify, e.g. agent://namespace/name")

    class CreduentVerifyTool(BaseTool):
        name: str = "Creduent Agent Verification"
        description: str = "Verifies the cryptographic identity and attestations of an external AI agent using the Creduent protocol."
        args_schema: type[BaseModel] = CreduentVerifyInput
        strict: bool = True

        def _run(self, agent_uri: str) -> str:
            """Execute the verification process."""
            logger.info(f"Verifying agent via CreduentVerifyTool: {agent_uri}")
            try:
                result = verify(agent_uri)
                if result.valid:
                    return f"Verification SUCCESS for {agent_uri}. Agent capabilities and keys are trusted."
                else:
                    error_msg = f"Verification failed for {agent_uri}: {result.error}"
                    logger.warning(error_msg)
                    if self.strict:
                        raise VerificationError(error_msg)
                    return f"Verification FAILED: {error_msg}"
            except Exception as e:
                error_msg = f"Verification process failed: {str(e)}"
                logger.error(error_msg)
                if self.strict and not isinstance(e, VerificationError):
                    raise VerificationError(error_msg) from e
                elif self.strict:
                    raise
                return f"Verification FAILED: {error_msg}"

else:
    class CreduentVerifyTool:
        def __init__(self, *args, **kwargs):
            raise ImportError(
                "CrewAI is not installed. Please install it using: pip install creduent[crewai]"
            )
