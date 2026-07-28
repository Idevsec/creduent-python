import logging
from typing import Any, Dict, Optional, List

try:
    from langchain_core.tools import BaseTool
    from langchain_core.callbacks import BaseCallbackHandler
    from pydantic import BaseModel, Field

    HAS_LANGCHAIN = True
except ImportError:
    HAS_LANGCHAIN = False

    class BaseTool:
        pass

    class BaseCallbackHandler:
        pass

    class BaseModel:
        pass

    def Field(*args, **kwargs):
        return None


from creduent.verify import verify
from creduent.exceptions import VerificationError

logger = logging.getLogger(__name__)

if HAS_LANGCHAIN:

    class CreduentVerifyInput(BaseModel):
        agent_uri: str = Field(
            ...,
            description="The Creduent URI of the agent to verify, e.g. agent://namespace/name",
        )

    class CreduentLangChainTool(BaseTool):
        name: str = "creduent_verify_agent"
        description: str = "Verifies the cryptographic identity and attestations of an external AI agent using the Creduent protocol."
        args_schema: type[BaseModel] = CreduentVerifyInput
        strict: bool = True

        def _run(self, agent_uri: str) -> str:
            """Execute the verification process."""
            logger.info(f"Verifying agent via CreduentLangChainTool: {agent_uri}")
            try:
                result = verify(agent_uri)
                if result.valid:
                    return f"Verification SUCCESS for {agent_uri}. Agent identity and attestations are trusted."
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

    class CreduentLangChainCallbackHandler(BaseCallbackHandler):
        """Callback handler to enforce Creduent zero-trust identity verification on LangChain tool execution."""

        def __init__(self, target_agent_uris: Optional[List[str]] = None, strict: bool = True):
            super().__init__()
            self.target_agent_uris = target_agent_uris or []
            self.strict = strict

        def on_tool_start(
            self, serialized: Dict[str, Any], input_str: str, **kwargs: Any
        ) -> Any:
            """Intercept tool execution and verify target agent URIs if present."""
            for agent_uri in self.target_agent_uris:
                logger.info(f"[CreduentLangChainCallback] Pre-execution check for: {agent_uri}")
                result = verify(agent_uri)
                if not result.valid and self.strict:
                    raise VerificationError(
                        f"LangChain tool execution blocked. Agent verification failed for {agent_uri}: {result.error}"
                    )

else:

    class CreduentLangChainTool:
        def __init__(self, *args, **kwargs):
            raise ImportError(
                "LangChain is not installed. Please install it using: pip install langchain-core"
            )

    class CreduentLangChainCallbackHandler:
        def __init__(self, *args, **kwargs):
            raise ImportError(
                "LangChain is not installed. Please install it using: pip install langchain-core"
            )
