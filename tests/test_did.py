"""
Unit tests for Creduent W3C DID Interoperability module (creduent.did).
"""

import pytest
from creduent.did import agent_to_did, did_to_agent, agent_to_did_document


def test_agent_to_did_creduent_scheme():
    agent_id = "agent://idevsec/steward"
    did_uri = agent_to_did(agent_id, method="creduent")
    assert did_uri == "did:creduent:idevsec:steward"


def test_agent_to_did_web_scheme():
    agent_id = "agent://idevsec/steward"
    did_uri = agent_to_did(agent_id, method="web", domain="idevsec.com")
    assert did_uri == "did:web:idevsec.com:agent:steward"


def test_did_to_agent_creduent_scheme():
    did_uri = "did:creduent:idevsec:steward"
    agent_id = did_to_agent(did_uri)
    assert agent_id == "agent://idevsec/steward"


def test_did_to_agent_web_scheme():
    did_uri = "did:web:idevsec.com:agent:steward"
    agent_id = did_to_agent(did_uri)
    assert agent_id == "agent://idevsec/steward"


def test_agent_to_did_document():
    agent_data = {
        "agent_id": "agent://idevsec/steward",
        "public_key": "ed25519:7c9ab1...",
        "endpoint": "https://api.idevsec.com"
    }
    did_doc = agent_to_did_document(agent_data, method="creduent")

    assert did_doc["id"] == "did:creduent:idevsec:steward"
    assert did_doc["alsoKnownAs"] == ["agent://idevsec/steward"]
    assert len(did_doc["verificationMethod"]) == 1
    assert did_doc["verificationMethod"][0]["id"] == "did:creduent:idevsec:steward#key-1"
    assert did_doc["verificationMethod"][0]["publicKeyMultibase"] == "ed25519:7c9ab1..."
    assert len(did_doc["service"]) == 1
    assert did_doc["service"][0]["serviceEndpoint"] == "https://api.idevsec.com"


def test_invalid_agent_id():
    with pytest.raises(ValueError):
        agent_to_did("http://invalid.com/agent")

    with pytest.raises(ValueError):
        agent_to_did("agent://invalid")
