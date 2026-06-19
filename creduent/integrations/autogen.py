import logging
from typing import Any, Dict, Optional, Union, List, Tuple

try:
    from autogen import ConversableAgent, Agent
    HAS_AUTOGEN = True
except ImportError:
    HAS_AUTOGEN = False
    class ConversableAgent: pass

from creduent.verify import verify
from creduent.exceptions import VerificationError

logger = logging.getLogger(__name__)

if HAS_AUTOGEN:
    class CreduentConversableAgent(ConversableAgent):
        """
        A subclass of AutoGen's ConversableAgent that forces incoming messages
        to be verified if the sender claims an identity via Creduent.
        """
        def __init__(self, name: str, strict_verification: bool = True, **kwargs):
            super().__init__(name=name, **kwargs)
            self.strict_verification = strict_verification
            # Register a hook to run before standard message processing
            self.register_reply(
                [Agent, None],
                self._verify_sender_identity,
                position=0
            )

        def _verify_sender_identity(
            self,
            recipient: "ConversableAgent",
            messages: Optional[List[Dict]] = None,
            sender: Optional["Agent"] = None,
            config: Optional[Any] = None,
        ) -> Tuple[bool, Union[str, Dict, None]]:
            if not messages:
                return False, None
            
            last_message = messages[-1]
            agent_uri = last_message.get("agent_uri")
            
            # If no URI is provided, decide based on strict mode
            if not agent_uri:
                if self.strict_verification:
                    sender_name = sender.name if sender else 'Unknown'
                    raise VerificationError(f"Agent '{sender_name}' did not provide an agent_uri.")
                return False, None
            
            logger.info(f"AutoGen agent '{self.name}' verifying incoming sender '{agent_uri}'")
            try:
                result = verify(agent_uri)
                if not result.valid:
                    error_msg = f"Verification failed for {agent_uri}: {result.error}"
                    logger.warning(error_msg)
                    if self.strict_verification:
                        raise VerificationError(error_msg)
                    # In non-strict mode, we silently flag the message for the LLM
                    last_message["content"] = f"[WARNING: SENDER NOT VERIFIED] " + str(last_message.get("content", ""))
                
                # We return False, None to allow AutoGen to continue to the next reply function
                return False, None 
            except Exception as e:
                error_msg = f"Verification process failed: {str(e)}"
                logger.error(error_msg)
                if self.strict_verification and not isinstance(e, VerificationError):
                    raise VerificationError(error_msg) from e
                elif self.strict_verification:
                    raise
                return False, None
else:
    class CreduentConversableAgent:
        def __init__(self, *args, **kwargs):
            raise ImportError(
                "AutoGen is not installed. Please install it using: pip install creduent[autogen]"
            )
