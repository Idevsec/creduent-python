import hashlib
import json
import logging
from typing import Any, Dict, List, Optional, Tuple
from creduent.provenance import ReversibilityClass, REVERSIBILITY_PRECEDENCE, normalize_reversibility_class
from creduent.utils import safe_requests_get

logger = logging.getLogger(__name__)


class LedgerIntegrityError(Exception):
    """Raised when ledger hash chain or step-count verification fails."""

    pass


class LedgerClient:
    """Client for querying the independent Creduent Ledger registry for chain metadata."""

    def __init__(self, base_url: str = "https://creduent.idevsec.com"):
        self.base_url = base_url.rstrip("/")

    def get_chain_metadata(self, chain_id: str) -> Dict[str, Any]:
        """Queries the independent Creduent ledger for chain metadata.

        Args:
            chain_id: The unique identifier of the linked receipt chain.

        Returns:
            Dict containing total_steps, latest_hash, and status.

        Raises:
            LedgerIntegrityError: If chain cannot be retrieved from ledger.
        """
        url = f"{self.base_url}/ledger/chain/{chain_id}"
        try:
            response = safe_requests_get(url, timeout=5)
            if response.status_code == 200:
                return response.json()
            raise LedgerIntegrityError(
                f"Failed to query ledger for chain '{chain_id}': HTTP status {response.status_code}"
            )
        except Exception as e:
            if isinstance(e, LedgerIntegrityError):
                raise
            raise LedgerIntegrityError(f"Ledger connectivity failure for chain '{chain_id}': {e}") from e


class LedgerChainVerifier:
    """Verifies cryptographic chain integrity and computes worst-case reversibility for multi-step agent plans."""

    @staticmethod
    def verify_ledger_chain(receipts: List[Dict[str, Any]]) -> bool:
        """Verifies that receipts form a valid, un-truncated hash chain.

        Args:
            receipts: Sequential list of execution receipts.

        Returns:
            bool: True if chain hash links and sequence indices are valid.

        Raises:
            LedgerIntegrityError: If chain is broken or step indices are inconsistent.
        """
        if not receipts:
            raise LedgerIntegrityError("Receipt chain is empty.")

        prev_hash = "GENESIS"

        for idx, receipt in enumerate(receipts):
            step_index = receipt.get("step_index", idx)
            if step_index != idx:
                raise LedgerIntegrityError(
                    f"Chain step index mismatch at pos {idx}: expected {idx}, got {step_index}"
                )

            recorded_prev_hash = receipt.get("previous_receipt_hash", "GENESIS")
            if recorded_prev_hash != prev_hash:
                raise LedgerIntegrityError(
                    f"Chain hash mismatch at step {idx}: recorded prev {recorded_prev_hash}, expected {prev_hash}"
                )

            # Compute hash of current receipt content
            receipt_core = {
                "step_index": step_index,
                "agent_id": receipt.get("agent_id"),
                "tool_name": receipt.get("tool_name"),
                "reversibility_class": receipt.get("reversibility_class"),
                "previous_receipt_hash": recorded_prev_hash,
            }
            canonical_bytes = json.dumps(receipt_core, sort_keys=True).encode("utf-8")
            prev_hash = hashlib.sha256(canonical_bytes).hexdigest()

        return True

    @classmethod
    def reduce_worst_case_reversibility(
        cls,
        receipts: List[Dict[str, Any]],
        chain_id: Optional[str] = None,
        ledger_client: Optional[LedgerClient] = None,
    ) -> Tuple[str, int]:
        """Validates ledger chain integrity and computes worst-case reversibility across all steps.

        If a chain_id is provided or embedded in the receipts, queries the independent Creduent
        ledger to verify that the payload contains the full, untruncated receipt set.

        Args:
            receipts: Sequential list of execution receipts anchored from GENESIS.
            chain_id: Optional unique identifier of the chain in the Creduent ledger.
            ledger_client: Optional custom LedgerClient instance for querying ledger metadata.

        Returns:
            Tuple[str, int]: (Governing worst-case reversibility class, Validated step count).

        Raises:
            LedgerIntegrityError: If hash chain continuity breaks or if chain count disagrees with independent ledger record.
        """
        if not receipts:
            raise LedgerIntegrityError("Receipt chain is empty.")

        # 1. Verify hash chain continuity from GENESIS
        cls.verify_ledger_chain(receipts)

        # 2. Independent Ledger Count Check
        target_chain_id = chain_id or receipts[0].get("chain_id")
        if target_chain_id and ledger_client:
            ledger_meta = ledger_client.get_chain_metadata(target_chain_id)
            expected_total = ledger_meta.get("total_steps")
            if expected_total is not None and len(receipts) != expected_total:
                raise LedgerIntegrityError(
                    f"Chain Truncation Attack Detected: Independent ledger records {expected_total} steps for chain '{target_chain_id}', "
                    f"but payload only contains {len(receipts)} steps."
                )

        validated_count = len(receipts)

        worst_case = ReversibilityClass.READ_ONLY.value
        highest_rank = 0

        for receipt in receipts:
            raw_class = normalize_reversibility_class(
                tool_metadata={
                    "name": receipt.get("tool_name"),
                    "reversibility_class": receipt.get("reversibility_class"),
                },
                provenance_source=receipt.get("provenance_source"),
                is_registry_bound=receipt.get("is_registry_bound", False),
            )

            rank = 0
            for idx, member in enumerate(REVERSIBILITY_PRECEDENCE):
                if member.value == raw_class:
                    rank = idx
                    break

            if rank > highest_rank:
                highest_rank = rank
                worst_case = raw_class

        logger.info(
            f"[LedgerChainVerifier] Chain validated: {validated_count} steps, "
            f"governing class: {worst_case}"
        )
        return worst_case, validated_count

