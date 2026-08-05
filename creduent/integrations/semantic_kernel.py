import logging
from typing import Any, Dict, Optional

try:
    from semantic_kernel.functions import kernel_function

    HAS_SEMANTIC_KERNEL = True
except ImportError:
    HAS_SEMANTIC_KERNEL = False

    def kernel_function(*args, **kwargs):
        def decorator(func):
            return func

        return decorator


from creduent.verify import verify
from creduent.exceptions import VerificationError
from creduent.provenance import normalize_reversibility_class

logger = logging.getLogger(__name__)


class CreduentSemanticKernelPlugin:
    """Microsoft Semantic Kernel Plugin for Creduent Zero-Trust Agent Identity Verification."""

    @kernel_function(
        name="verify_agent",
        description="Verifies the cryptographic identity and attestations of an external AI agent using the Creduent protocol.",
    )
    def verify_agent(
        self,
        agent_uri: str,
        tool_metadata: Optional[Dict[str, Any]] = None,
        provenance_source: Optional[str] = None,
        is_registry_bound: bool = False,
    ) -> str:
        """Normalizes tool reversibility class at adapter boundary, then verifies the given agent URI."""
        reversibility_class = normalize_reversibility_class(
            tool_metadata=tool_metadata or {},
            provenance_source=provenance_source,
            is_registry_bound=is_registry_bound,
        )
        logger.info(
            f"[CreduentSK] Tool reversibility normalized to: {reversibility_class} "
            f"before verifying agent: {agent_uri}"
        )
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
