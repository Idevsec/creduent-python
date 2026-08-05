import pytest
from creduent.provenance import (
    ProvenanceGuard,
    ReversibilityClass,
    normalize_reversibility_class,
)
from creduent.ledger import LedgerChainVerifier, LedgerIntegrityError


def test_provenance_guard_missing_metadata():
    """Test that missing tool metadata resolves to IRREVERSIBLE (fail-closed)."""
    assert normalize_reversibility_class(None) == ReversibilityClass.IRREVERSIBLE.value
    assert normalize_reversibility_class({}) == ReversibilityClass.IRREVERSIBLE.value


def test_provenance_guard_unclassified_tool():
    """Test that tool metadata missing reversibility keys resolves to IRREVERSIBLE."""
    metadata = {"name": "search_db"}
    assert normalize_reversibility_class(metadata) == ReversibilityClass.IRREVERSIBLE.value


def test_provenance_guard_self_assertion_override():
    """Test that self-asserted read_only class without registry provenance is overridden to IRREVERSIBLE."""
    metadata = {"name": "query_tool", "reversibility_class": "read_only"}
    # Without registry binding or trusted provenance, self-assertion resolves to IRREVERSIBLE
    normalized = normalize_reversibility_class(
        metadata, provenance_source=None, is_registry_bound=False
    )
    assert normalized == ReversibilityClass.IRREVERSIBLE.value


def test_provenance_guard_trusted_registry_bound():
    """Test that trusted registry-bound reversibility class is accepted."""
    metadata = {"name": "query_tool", "reversibility_class": "read_only"}
    normalized = normalize_reversibility_class(
        metadata,
        provenance_source="https://creduent.idevsec.com",
        is_registry_bound=True,
    )
    assert normalized == ReversibilityClass.READ_ONLY.value


def test_provenance_guard_vocabulary_canonicalization():
    """Test mapping of alternative/legacy vocabulary to standard AISVS C9.2.3 classes."""
    guard = ProvenanceGuard(trusted_registries={"https://creduent.idevsec.com"})

    meta_local = {"name": "t1", "reversibility_class": "recoverable_local"}
    meta_non_rec = {"name": "t2", "reversibility_class": "non_recoverable"}

    assert (
        guard.normalize(
            meta_local, provenance_source="https://creduent.idevsec.com", is_registry_bound=True
        )
        == ReversibilityClass.REVERSIBLE.value
    )
    assert (
        guard.normalize(
            meta_non_rec, provenance_source="https://creduent.idevsec.com", is_registry_bound=True
        )
        == ReversibilityClass.IRREVERSIBLE.value
    )


def test_ledger_verifier_worst_case_reduction():
    """Test worst-case reduction across valid linked ledger receipts."""
    receipts = [
        {
            "step_index": 0,
            "agent_id": "agent://ns/a1",
            "tool_name": "read_db",
            "reversibility_class": "read_only",
            "previous_receipt_hash": "GENESIS",
            "provenance_source": "https://creduent.idevsec.com",
            "is_registry_bound": True,
        },
        {
            "step_index": 1,
            "agent_id": "agent://ns/a1",
            "tool_name": "update_cache",
            "reversibility_class": "reversible",
            "previous_receipt_hash": "3ef86d77ecc52febefef43ddb790e65eed6f16245375d4f087366adf88241178",
            "provenance_source": "https://creduent.idevsec.com",
            "is_registry_bound": True,
        },
    ]

    # No caller-supplied count: chain length derived from GENESIS traversal
    worst_case, count = LedgerChainVerifier.reduce_worst_case_reversibility(receipts)
    assert worst_case == ReversibilityClass.REVERSIBLE.value
    assert count == 2


def test_ledger_verifier_broken_hash_chain():
    """Test detection of a tampered or truncated chain via broken hash links.

    This covers Mayur's finding: a caller who sends a truncated list AND a matching count
    would have previously passed. Now, no caller count is accepted — the chain GENESIS
    traversal itself detects the break.
    """
    receipts = [
        {
            "step_index": 0,
            "agent_id": "agent://ns/a1",
            "tool_name": "read_db",
            "reversibility_class": "read_only",
            "previous_receipt_hash": "GENESIS",
            "provenance_source": "https://creduent.idevsec.com",
            "is_registry_bound": True,
        },
        {
            "step_index": 1,
            "agent_id": "agent://ns/a1",
            "tool_name": "delete_record",
            "reversibility_class": "irreversible",
            # Deliberately WRONG previous hash — simulates chain break / tampered receipt
            "previous_receipt_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "provenance_source": "https://creduent.idevsec.com",
            "is_registry_bound": True,
        },
    ]

    with pytest.raises(LedgerIntegrityError) as exc_info:
        LedgerChainVerifier.reduce_worst_case_reversibility(receipts)

    assert "Chain hash mismatch" in str(exc_info.value)


def test_ledger_client_truncation_detection():
    """Test independent ledger query detecting truncated payload receipts."""
    from unittest.mock import MagicMock

    receipts = [
        {
            "chain_id": "chain_abc123",
            "step_index": 0,
            "agent_id": "agent://ns/a1",
            "tool_name": "read_db",
            "reversibility_class": "read_only",
            "previous_receipt_hash": "GENESIS",
            "provenance_source": "https://creduent.idevsec.com",
            "is_registry_bound": True,
        }
    ]

    mock_client = MagicMock()
    # Mock ledger registry returns that the chain actually contains 3 steps in total
    mock_client.get_chain_metadata.return_value = {
        "chain_id": "chain_abc123",
        "total_steps": 3,
        "latest_hash": "some_hash",
    }

    with pytest.raises(LedgerIntegrityError) as exc_info:
        LedgerChainVerifier.reduce_worst_case_reversibility(
            receipts, chain_id="chain_abc123", ledger_client=mock_client
        )

    assert "Chain Truncation Attack Detected" in str(exc_info.value)
    assert "records 3 steps" in str(exc_info.value)

