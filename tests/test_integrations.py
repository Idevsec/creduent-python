import pytest
from unittest.mock import patch, MagicMock
import sys

# Mock crewai and pydantic before importing our integration
class DummyModule:
    pass

crewai_tools_mod = DummyModule()
class DummyBaseTool: pass
crewai_tools_mod.BaseTool = DummyBaseTool

sys.modules['crewai'] = DummyModule()
sys.modules['crewai.tools'] = crewai_tools_mod

class DummyPydantic:
    class BaseModel: pass
    def Field(self, *args, **kwargs): return None
sys.modules['pydantic'] = DummyPydantic()

# Mock autogen
autogen_mod = DummyModule()
class DummyConversableAgent:
    def __init__(self, name=None, *args, **kwargs): 
        self.name = name
class DummyAgentBase: pass
autogen_mod.ConversableAgent = DummyConversableAgent
autogen_mod.Agent = DummyAgentBase
sys.modules['autogen'] = autogen_mod

# Now we can safely import our modules
from creduent.exceptions import VerificationError
from creduent.integrations.langgraph import verify_agent_node
import creduent.integrations.crewai as crewai_integ
import creduent.integrations.autogen as autogen_integ

def make_mock_result(valid=True, error=None):
    mock = MagicMock()
    mock.valid = valid
    mock.error = error
    mock.agent_id = "test_agent"
    mock.public_key = "test_key"
    mock.endpoint = "test_endpoint"
    mock.capabilities = []
    return mock

@patch('creduent.integrations.langgraph.verify')
def test_langgraph_verify_node_success(mock_verify):
    mock_verify.return_value = make_mock_result(valid=True)
    state = {"agent_uri": "agent://test/test"}
    
    new_state = verify_agent_node(state)
    assert new_state["verification_result"]["verified"] is True

@patch('creduent.integrations.langgraph.verify')
def test_langgraph_verify_node_failure_strict(mock_verify):
    mock_verify.return_value = make_mock_result(valid=False, error="Invalid signature")
    state = {"agent_uri": "agent://test/test"}
    
    with pytest.raises(VerificationError):
        verify_agent_node(state, strict=True)

@patch('creduent.integrations.langgraph.verify')
def test_langgraph_verify_node_failure_non_strict(mock_verify):
    mock_verify.return_value = make_mock_result(valid=False, error="Invalid signature")
    state = {"agent_uri": "agent://test/test"}
    
    new_state = verify_agent_node(state, strict=False)
    assert new_state["verification_result"]["verified"] is False

@patch('creduent.integrations.crewai.verify')
def test_crewai_tool_success(mock_verify):
    # Enable the flag for tests
    crewai_integ.HAS_CREWAI = True
    
    mock_verify.return_value = make_mock_result(valid=True)
    
    # We mock the class since BaseTool is mocked
    class DummyTool(crewai_integ.CreduentVerifyTool):
        pass
        
    tool = DummyTool()
    tool.strict = True
    
    result = tool._run("agent://test/crew")
    assert "SUCCESS" in result

@patch('creduent.integrations.crewai.verify')
def test_crewai_tool_failure(mock_verify):
    crewai_integ.HAS_CREWAI = True
    mock_verify.return_value = make_mock_result(valid=False, error="Bad")
    
    class DummyTool(crewai_integ.CreduentVerifyTool):
        pass
        
    tool = DummyTool()
    tool.strict = True
    
    with pytest.raises(VerificationError):
        tool._run("agent://test/crew")

@patch('creduent.integrations.autogen.verify')
def test_autogen_agent_success(mock_verify):
    autogen_integ.HAS_AUTOGEN = True
    mock_verify.return_value = make_mock_result(valid=True)
    
    class DummyAgent(autogen_integ.CreduentConversableAgent):
        def register_reply(self, *args, **kwargs):
            pass # mock
            
    agent = DummyAgent("test_agent")
    
    mock_sender = MagicMock()
    mock_sender.name = "remote_agent"
    
    # Test message with URI
    messages = [{"content": "hello", "agent_uri": "agent://test/auto"}]
    
    continue_flag, reply = agent._verify_sender_identity(
        recipient=agent, 
        messages=messages, 
        sender=mock_sender
    )
    
    # Should return False, None to continue to next reply function
    assert continue_flag is False
    assert reply is None
