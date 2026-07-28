"""
Creduent Protocol Framework Integrations

This module provides native integrations for popular AI agent frameworks
including CrewAI, LangGraph, AutoGen, LangChain, LlamaIndex, Semantic Kernel, and Google ADK.
"""

from creduent.integrations.crewai import CreduentVerifyTool
from creduent.integrations.langgraph import verify_agent_node
from creduent.integrations.autogen import CreduentConversableAgent
from creduent.integrations.langchain import CreduentLangChainTool, CreduentLangChainCallbackHandler
from creduent.integrations.llamaindex import create_creduent_llamaindex_tool
from creduent.integrations.semantic_kernel import CreduentSemanticKernelPlugin
from creduent.integrations.google_adk import CreduentGoogleADKPlugin

__all__ = [
    "CreduentVerifyTool",
    "verify_agent_node",
    "CreduentConversableAgent",
    "CreduentLangChainTool",
    "CreduentLangChainCallbackHandler",
    "create_creduent_llamaindex_tool",
    "CreduentSemanticKernelPlugin",
    "CreduentGoogleADKPlugin",
]
