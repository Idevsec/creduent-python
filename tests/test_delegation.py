import base64
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

import pytest

from creduent.delegation import (
    sign_delegation,
    verify_delegation_chain,
    sign_pop_header,
    verify_pop_header,
    DelegationError,
)


def _make_keypair():
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    pub_str = f"ed25519:{base64.b64encode(pub_bytes).decode('utf-8')}"
    return priv, pub_str


def test_sign_delegation_basic():
    root_priv, root_pub = _make_keypair()
    child_priv, child_pub = _make_keypair()

    cdt = sign_delegation(
        delegator_private_key=root_priv,
        delegator_uri="agent://corp/orchestrator",
        delegate_uri="agent://corp/subagent",
        delegate_public_key=child_pub,
        constraints={
            "allowed_capabilities": ["scan", "query"],
            "max_reversibility": "reversible",
            "allowed_tools": ["search_db", "fetch_url"],
        },
        intent_hash="sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ttl_seconds=1800,
    )

    assert cdt["version"] == "1.0"
    assert cdt["delegator"] == "agent://corp/orchestrator"
    assert cdt["delegate"] == "agent://corp/subagent"
    assert cdt["delegate_public_key"] == child_pub
    assert "signature" in cdt
    assert cdt["constraints"]["allowed_capabilities"] == ["scan", "query"]

    # Verify chain of 1 hop
    res = verify_delegation_chain(
        cdt_chain=[cdt],
        trusted_public_keys={"agent://corp/orchestrator": root_pub},
    )
    assert res.valid is True
    assert res.chain_depth == 1
    assert res.root_delegator == "agent://corp/orchestrator"
    assert res.leaf_delegate == "agent://corp/subagent"


def test_tampered_cdt_signature_failure():
    root_priv, root_pub = _make_keypair()
    child_priv, child_pub = _make_keypair()

    cdt = sign_delegation(
        delegator_private_key=root_priv,
        delegator_uri="agent://corp/orchestrator",
        delegate_uri="agent://corp/subagent",
        delegate_public_key=child_pub,
        constraints={"allowed_capabilities": ["scan"]},
    )

    # Tamper with constraints
    cdt["constraints"]["allowed_capabilities"] = ["scan", "admin_root"]

    res = verify_delegation_chain(
        cdt_chain=[cdt],
        trusted_public_keys={"agent://corp/orchestrator": root_pub},
    )
    assert res.valid is False
    assert res.error_code == "CDT_SIGNATURE_INVALID"


def test_pop_header_signing_and_verification():
    child_priv, child_pub = _make_keypair()
    token_id = "urn:uuid:12345678-1234-5678-1234-567812345678"

    pop_sig, timestamp = sign_pop_header(
        delegate_private_key=child_priv,
        http_method="POST",
        uri_path="/api/v1/tools/search",
        token_id=token_id,
    )

    # Verify valid
    is_valid = verify_pop_header(
        pop_signature=pop_sig,
        timestamp=timestamp,
        delegate_public_key=child_pub,
        http_method="POST",
        uri_path="/api/v1/tools/search",
        token_id=token_id,
    )
    assert is_valid is True

    # Verify wrong path fails
    assert verify_pop_header(
        pop_signature=pop_sig,
        timestamp=timestamp,
        delegate_public_key=child_pub,
        http_method="POST",
        uri_path="/api/v1/tools/delete",
        token_id=token_id,
    ) is False

    # Verify expired timestamp (> 60s) fails
    old_time = (datetime.now(timezone.utc) - timedelta(seconds=120)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert verify_pop_header(
        pop_signature=pop_sig,
        timestamp=old_time,
        delegate_public_key=child_pub,
        http_method="POST",
        uri_path="/api/v1/tools/search",
        token_id=token_id,
        max_skew_seconds=60,
    ) is False


def test_multi_hop_delegation_chain_with_pop():
    root_priv, root_pub = _make_keypair()
    mid_priv, mid_pub = _make_keypair()
    leaf_priv, leaf_pub = _make_keypair()

    # Hop 1: Root -> Mid
    cdt1 = sign_delegation(
        delegator_private_key=root_priv,
        delegator_uri="agent://corp/root",
        delegate_uri="agent://corp/mid",
        delegate_public_key=mid_pub,
        constraints={
            "allowed_capabilities": ["read", "write"],
            "max_reversibility": "reversible",
            "allowed_tools": ["db_read", "db_write"],
        },
    )

    # Hop 2: Mid -> Leaf (narrowed)
    cdt2 = sign_delegation(
        delegator_private_key=mid_priv,
        delegator_uri="agent://corp/mid",
        delegate_uri="agent://corp/leaf",
        delegate_public_key=leaf_pub,
        constraints={
            "allowed_capabilities": ["read"],
            "max_reversibility": "read-only",
            "allowed_tools": ["db_read"],
        },
    )

    # Leaf generates PoP
    pop_sig, pop_ts = sign_pop_header(
        delegate_private_key=leaf_priv,
        http_method="GET",
        uri_path="/query",
        token_id=cdt2["token_id"],
    )

    # Verify full chain + PoP
    res = verify_delegation_chain(
        cdt_chain=[cdt1, cdt2],
        target_action="db_read",
        required_capability="read",
        pop_signature=pop_sig,
        pop_timestamp=pop_ts,
        http_method="GET",
        uri_path="/query",
        trusted_public_keys={"agent://corp/root": root_pub},
    )

    assert res.valid is True
    assert res.chain_depth == 2
    assert res.root_delegator == "agent://corp/root"
    assert res.leaf_delegate == "agent://corp/leaf"


def test_privilege_escalation_detection():
    root_priv, root_pub = _make_keypair()
    mid_priv, mid_pub = _make_keypair()
    leaf_priv, leaf_pub = _make_keypair()

    # Root only grants "read"
    cdt1 = sign_delegation(
        delegator_private_key=root_priv,
        delegator_uri="agent://corp/root",
        delegate_uri="agent://corp/mid",
        delegate_public_key=mid_pub,
        constraints={"allowed_capabilities": ["read"]},
    )

    # Mid tries to grant "admin_write" (Privilege Escalation!)
    cdt2 = sign_delegation(
        delegator_private_key=mid_priv,
        delegator_uri="agent://corp/mid",
        delegate_uri="agent://corp/leaf",
        delegate_public_key=leaf_pub,
        constraints={"allowed_capabilities": ["read", "admin_write"]},
    )

    res = verify_delegation_chain(
        cdt_chain=[cdt1, cdt2],
        trusted_public_keys={"agent://corp/root": root_pub},
    )

    assert res.valid is False
    assert res.error_code == "CDT_PRIVILEGE_ESCALATION"


def test_reversibility_escalation_detection():
    root_priv, root_pub = _make_keypair()
    mid_priv, mid_pub = _make_keypair()
    leaf_priv, leaf_pub = _make_keypair()

    # Root grants max_reversibility "reversible"
    cdt1 = sign_delegation(
        delegator_private_key=root_priv,
        delegator_uri="agent://corp/root",
        delegate_uri="agent://corp/mid",
        delegate_public_key=mid_pub,
        constraints={"max_reversibility": "reversible"},
    )

    # Mid tries to grant "irreversible"
    cdt2 = sign_delegation(
        delegator_private_key=mid_priv,
        delegator_uri="agent://corp/mid",
        delegate_uri="agent://corp/leaf",
        delegate_public_key=leaf_pub,
        constraints={"max_reversibility": "irreversible"},
    )

    res = verify_delegation_chain(
        cdt_chain=[cdt1, cdt2],
        trusted_public_keys={"agent://corp/root": root_pub},
    )

    assert res.valid is False
    assert res.error_code == "CDT_PRIVILEGE_ESCALATION"


def test_max_chain_depth_exceeded():
    root_priv, root_pub = _make_keypair()
    chain = []
    curr_priv = root_priv
    curr_pub = root_pub
    curr_uri = "agent://corp/agent0"

    # Create 9 hops (exceeding default limit of 8)
    for i in range(1, 10):
        next_priv, next_pub = _make_keypair()
        next_uri = f"agent://corp/agent{i}"
        cdt = sign_delegation(
            delegator_private_key=curr_priv,
            delegator_uri=curr_uri,
            delegate_uri=next_uri,
            delegate_public_key=next_pub,
            constraints={"allowed_capabilities": ["scan"]},
        )
        chain.append(cdt)
        curr_priv = next_priv
        curr_pub = next_pub
        curr_uri = next_uri

    res = verify_delegation_chain(
        cdt_chain=chain,
        max_chain_depth=8,
        trusted_public_keys={"agent://corp/agent0": root_pub},
    )
    assert res.valid is False
    assert res.error_code == "CDT_CHAIN_DEPTH_EXCEEDED"


def test_action_constraint_enforcement():
    root_priv, root_pub = _make_keypair()
    child_priv, child_pub = _make_keypair()

    cdt = sign_delegation(
        delegator_private_key=root_priv,
        delegator_uri="agent://corp/root",
        delegate_uri="agent://corp/child",
        delegate_public_key=child_pub,
        constraints={
            "allowed_capabilities": ["query"],
            "allowed_tools": ["safe_search"],
        },
    )

    # Allowed tool passes
    res_ok = verify_delegation_chain(
        cdt_chain=[cdt],
        target_action="safe_search",
        required_capability="query",
        trusted_public_keys={"agent://corp/root": root_pub},
    )
    assert res_ok.valid is True

    # Unauthorized tool fails
    res_bad = verify_delegation_chain(
        cdt_chain=[cdt],
        target_action="drop_database",
        trusted_public_keys={"agent://corp/root": root_pub},
    )
    assert res_bad.valid is False
    assert res_bad.error_code == "CDT_CONSTRAINT_VIOLATION"

