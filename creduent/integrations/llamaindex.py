import logging
from typing import Any, Dict, Optional

try:
    from llama_index.core.tools import FunctionTool
    from pydantic import BaseModel, Field

    HAS_LLAMAINDEX = True
except ImportError:
    HAS_LLAMAINDEX = False

    class FunctionTool:
        pass

    class BaseModel:
        pass


from creduent.verify import verify
from creduent.exceptions import VerificationError

logger = logging.getLogger(__name__)


def creduent_verify_agent(agent_uri: str) -> str:
    """
    Verifies the cryptographic identity and attestations of an external AI agent using the Creduent protocol.

    Args:
        agent_uri: The Creduent URI of the agent, e.g. agent://namespace/name
    """
    logger.info(f"Verifying agent via Creduent LlamaIndex FunctionTool: {agent_uri}")
    try:
        result = verify(agent_uri)
        if result.valid:
            return f"Verification SUCCESS for {agent_uri}. Agent identity and attestations are trusted."
        else:
            error_msg = f"Verification failed for {agent_uri}: {result.error}"
            logger.warning(error_msg)
            raise VerificationError(error_msg)
    except Exception as e:
        error_msg = f"Verification process failed: {str(e)}"
        logger.error(error_msg)
        raise VerificationError(error_msg) from e


if HAS_LLAMAINDEX:

    def create_creduent_llamaindex_tool() -> FunctionTool:
        """Helper to instantiate a LlamaIndex FunctionTool for Creduent agent identity verification."""
        return FunctionTool.from_defaults(
            fn=creduent_verify_agent,
            name="creduent_verify_agent",
            description="Verifies the cryptographic identity and attestations of an external AI agent using the Creduent protocol.",
        )

else:

    def create_creduent_llamaindex_tool(*args, **kwargs):
        raise ImportError(
            "LlamaIndex is not installed. Please install it using: pip install llama-index-core"
        )
