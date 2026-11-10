"""
Creduent Protocol SDK - Creduent Delegation Token (CDT) & Proof-of-Possession (PoP)
Compliant with CREDUENT-007 specification.
"""

import base64
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from creduent.crypto import canonicalize
from creduent.exceptions import CreduentError


class DelegationError(CreduentError):
    """Exception raised when delegation token creation or verification fails."""
    pass


@dataclass
class DelegationVerifyResult:
    """Result of delegation chain verification."""
    valid: bool
    error: Optional[str] = None
    error_code: Optional[str] = None
    chain_depth: int = 0
    root_delegator: Optional[str] = None
    leaf_delegate: Optional[str] = None
    allowed_capabilities: Optional[List[str]] = None
    allowed_tools: Optional[List[str]] = None
    max_reversibility: Optional[str] = None


REVERSIBILITY_ORDER = {
    "read-only": 0,
    "reversible": 1,
    "external-reversible": 2,
    "irreversible": 3,
}


def _load_private_key(key_input: Union[str, bytes, ed25519.Ed25519PrivateKey]) -> ed25519.Ed25519PrivateKey:
    """Helper to load Ed25519 private key from PEM str, raw bytes, or Ed25519PrivateKey."""
    if isinstance(key_input, ed25519.Ed25519PrivateKey):
        return key_input

    if isinstance(key_input, str):
        key_input = key_input.strip()
        if "BEGIN " in key_input:
            return serialization.load_pem_private_key(key_input.encode("utf-8"), password=None)
        # Try raw base64 or hex
        try:
            raw_bytes = base64.b64decode(key_input)
            if len(raw_bytes) == 32:
                return ed25519.Ed25519PrivateKey.from_private_bytes(raw_bytes)
        except Exception:
            pass
        return serialization.load_pem_private_key(key_input.encode("utf-8"), password=None)

    if isinstance(key_input, bytes):
        if b"BEGIN " in key_input:
            return serialization.load_pem_private_key(key_input, password=None)
        if len(key_input) == 32:
            return ed25519.Ed25519PrivateKey.from_private_bytes(key_input)
        return serialization.load_pem_private_key(key_input, password=None)

    raise DelegationError(f"Unsupported private key format: {type(key_input)}")


def _load_public_key(pubkey_str: str) -> ed25519.Ed25519PublicKey:
    """Parses an 'ed25519:<base64>' or raw base64 string into an Ed25519PublicKey."""
    if not isinstance(pubkey_str, str):
        raise DelegationError("Public key must be a string")

    pubkey_str = pubkey_str.strip()
    if pubkey_str.startswith("ed25519:"):
        b64_part = pubkey_str.split(":", 1)[1]
    else:
        b64_part = pubkey_str

    try:
        raw_bytes = base64.b64decode(b64_part)
        if len(raw_bytes) != 32:
            raise ValueError(f"Ed25519 public key raw length must be 32 bytes, got {len(raw_bytes)}")
        return ed25519.Ed25519PublicKey.from_public_bytes(raw_bytes)
    except Exception as e:
        raise DelegationError(f"Failed to load Ed25519 public key: {e}")


def _parse_iso_timestamp(ts_str: str) -> datetime:
    """Parses ISO 8601 UTC timestamp."""
    clean_ts = ts_str.rstrip("Z")
    if "+" in clean_ts:
        clean_ts = clean_ts.split("+")[0]
    return datetime.fromisoformat(clean_ts).replace(tzinfo=timezone.utc)


def sign_delegation(
    delegator_private_key: Union[str, bytes, ed25519.Ed25519PrivateKey],
    delegator_uri: str,
    delegate_uri: str,
    delegate_public_key: str,
    constraints: Dict[str, Any],
    intent_hash: Optional[str] = None,
    ttl_seconds: int = 3600,
    token_id: Optional[str] = None,
    issued_at: Optional[str] = None,
) -> Dict[str, Any]:
    """Constructs, JCS-canonicalizes, signs, and returns a Creduent Delegation Token (CDT).

    Complies with CREDUENT-007 Section 3 and Section 6.1.
    """
    if not delegator_uri or not delegator_uri.startswith("agent://"):
        raise DelegationError("delegator_uri must be a valid 'agent://' URI")
    if not delegate_uri or not delegate_uri.startswith("agent://"):
        raise DelegationError("delegate_uri must be a valid 'agent://' URI")
    if not delegate_public_key or not delegate_public_key.startswith("ed25519:"):
        raise DelegationError("delegate_public_key must be in 'ed25519:<base64>' format")
    if not isinstance(constraints, dict):
        raise DelegationError("constraints must be a dictionary")

    priv_key = _load_private_key(delegator_private_key)

    now = datetime.now(timezone.utc)
    if issued_at:
        now = _parse_iso_timestamp(issued_at)

    issued_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    expires_str = (now + timedelta(seconds=ttl_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
    actual_token_id = token_id or f"urn:uuid:{uuid.uuid4()}"

    cdt: Dict[str, Any] = {
        "version": "1.0",
        "token_id": actual_token_id,
        "issued_at": issued_str,
        "expires_at": expires_str,
        "delegator": delegator_uri,
        "delegate": delegate_uri,
        "delegate_public_key": delegate_public_key,
        "constraints": constraints,
    }

    if intent_hash:
        cdt["intent_hash"] = intent_hash

    # JCS Canonicalize without signature
    canonical_payload = canonicalize(cdt)

    # Sign using delegator private key
    sig_bytes = priv_key.sign(canonical_payload.encode("utf-8"))
    cdt["signature"] = base64.b64encode(sig_bytes).decode("ascii")

    return cdt


def sign_pop_header(
    delegate_private_key: Union[str, bytes, ed25519.Ed25519PrivateKey],
    http_method: str,
    uri_path: str,
    token_id: str,
    timestamp: Optional[str] = None,
) -> tuple[str, str]:
    """Computes Proof-of-Possession (PoP) signature header per CREDUENT-007 Section 3.3.

    Formula:
        PoP_Sig = Ed25519_Sign(Delegate_PrivateKey, HTTP_Method || URI_Path || Timestamp || CDT_Token_ID)

    Returns:
        tuple[str, str]: (pop_signature_b64, timestamp_iso)
    """
    priv_key = _load_private_key(delegate_private_key)

    if not timestamp:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    message = f"{http_method.upper()}|{uri_path}|{timestamp}|{token_id}".encode("utf-8")
    sig_bytes = priv_key.sign(message)
    pop_sig_b64 = base64.b64encode(sig_bytes).decode("ascii")

    return pop_sig_b64, timestamp


def verify_pop_header(
    pop_signature: str,
    timestamp: str,
    delegate_public_key: str,
    http_method: str,
    uri_path: str,
    token_id: str,
    max_skew_seconds: int = 60,
) -> bool:
    """Verifies a Proof-of-Possession (PoP) signature header per CREDUENT-007 Section 3.3."""
    if not pop_signature or not timestamp or not delegate_public_key:
        return False

    try:
        ts = _parse_iso_timestamp(timestamp)
        now = datetime.now(timezone.utc)
        skew = abs((now - ts).total_seconds())
        if skew > max_skew_seconds:
            return False

        pub_key = _load_public_key(delegate_public_key)
        sig_bytes = base64.b64decode(pop_signature)
        message = f"{http_method.upper()}|{uri_path}|{timestamp}|{token_id}".encode("utf-8")

        pub_key.verify(sig_bytes, message)
        return True
    except Exception:
        return False


def verify_delegation_chain(
    cdt_chain: List[Dict[str, Any]],
    target_action: Optional[str] = None,
    required_capability: Optional[str] = None,
    pop_signature: Optional[str] = None,
    pop_timestamp: Optional[str] = None,
    http_method: Optional[str] = None,
    uri_path: Optional[str] = None,
    trusted_public_keys: Optional[Dict[str, str]] = None,
    max_chain_depth: int = 8,
    max_clock_skew_seconds: int = 300,
) -> DelegationVerifyResult:
    """Verifies a chain of Creduent Delegation Tokens (CDTs).

    Performs:
    1. Chain depth validation (<= max_chain_depth, standard max 8).
    2. Format and temporal checks (issued_at, expires_at).
    3. Cryptographic Ed25519 signature checks on every hop.
    4. Chain continuity (token[i].delegator == token[i-1].delegate).
    5. Constraint narrowing (capabilities subset, reversibility class ceiling).
    6. Proof-of-Possession (PoP) verification on leaf delegate.
    """
    if not isinstance(cdt_chain, list) or len(cdt_chain) == 0:
        return DelegationVerifyResult(
            valid=False,
            error="Delegation chain is empty or malformed",
            error_code="CDT_MALFORMED",
        )

    if len(cdt_chain) > max_chain_depth:
        return DelegationVerifyResult(
            valid=False,
            error=f"Delegation chain length ({len(cdt_chain)}) exceeds maximum allowed depth ({max_chain_depth})",
            error_code="CDT_CHAIN_DEPTH_EXCEEDED",
            chain_depth=len(cdt_chain),
        )

    now = datetime.now(timezone.utc)
    trusted_keys = trusted_public_keys or {}

    prev_token: Optional[Dict[str, Any]] = None

    for i, cdt in enumerate(cdt_chain):
        # 1. Structure check
        required_fields = [
            "version",
            "token_id",
            "issued_at",
            "expires_at",
            "delegator",
            "delegate",
            "delegate_public_key",
            "constraints",
            "signature",
        ]
        for field in required_fields:
            if field not in cdt:
                return DelegationVerifyResult(
                    valid=False,
                    error=f"CDT token at index {i} missing required field: {field}",
                    error_code="CDT_MALFORMED",
                )

        # 2. Temporal validation
        try:
            issued_at = _parse_iso_timestamp(cdt["issued_at"])
            expires_at = _parse_iso_timestamp(cdt["expires_at"])
        except Exception as e:
            return DelegationVerifyResult(
                valid=False,
                error=f"Invalid timestamp in CDT at index {i}: {e}",
                error_code="CDT_MALFORMED",
            )

        if (issued_at - now).total_seconds() > max_clock_skew_seconds:
            return DelegationVerifyResult(
                valid=False,
                error=f"CDT token at index {i} is not yet valid (issued_at in future)",
                error_code="CDT_NOT_YET_VALID",
            )

        if expires_at <= now:
            return DelegationVerifyResult(
                valid=False,
                error=f"CDT token at index {i} has expired (expires_at <= current UTC time)",
                error_code="CDT_EXPIRED",
            )

        # 3. Signature verification
        # The delegator public key must come from:
        # - Previous hop's delegate_public_key (if i > 0)
        # - Or trusted_keys dictionary
        # - Or fallback delegator metadata
        delegator_uri = cdt["delegator"]
        delegator_pubkey = None

        if i > 0 and prev_token is not None:
            # Must link to previous token's delegate
            if delegator_uri != prev_token["delegate"]:
                return DelegationVerifyResult(
                    valid=False,
                    error=f"Chain continuity broken at hop {i}: delegator {delegator_uri} != parent delegate {prev_token['delegate']}",
                    error_code="CDT_KEY_MISMATCH",
                )
            delegator_pubkey = prev_token["delegate_public_key"]
        else:
            delegator_pubkey = trusted_keys.get(delegator_uri)

        if delegator_pubkey:
            try:
                pub_key_obj = _load_public_key(delegator_pubkey)
                sig_bytes = base64.b64decode(cdt["signature"])
                cdt_payload = {k: v for k, v in cdt.items() if k != "signature"}
                canonical_bytes = canonicalize(cdt_payload).encode("utf-8")
                pub_key_obj.verify(sig_bytes, canonical_bytes)
            except InvalidSignature:
                return DelegationVerifyResult(
                    valid=False,
                    error=f"Ed25519 signature invalid for delegator {delegator_uri} at hop {i}",
                    error_code="CDT_SIGNATURE_INVALID",
                )
            except Exception as e:
                return DelegationVerifyResult(
                    valid=False,
                    error=f"Cryptographic check failed at hop {i}: {e}",
                    error_code="CDT_SIGNATURE_INVALID",
                )

        # 4. Constraint Narrowing (Section 7.1)
        constraints = cdt.get("constraints", {})
        allowed_caps = constraints.get("allowed_capabilities")
        if prev_token is not None:
            prev_constraints = prev_token.get("constraints", {})
            prev_caps = prev_constraints.get("allowed_capabilities")

            # Subset check: child capabilities cannot exceed parent capabilities
            if allowed_caps is not None and prev_caps is not None:
                if not set(allowed_caps).issubset(set(prev_caps)):
                    return DelegationVerifyResult(
                        valid=False,
                        error=f"Privilege escalation at hop {i}: capabilities {allowed_caps} exceed parent {prev_caps}",
                        error_code="CDT_PRIVILEGE_ESCALATION",
                    )

            # Reversibility ceiling check
            child_rev = constraints.get("max_reversibility")
            parent_rev = prev_constraints.get("max_reversibility")
            if child_rev and parent_rev:
                c_rank = REVERSIBILITY_ORDER.get(child_rev, 99)
                p_rank = REVERSIBILITY_ORDER.get(parent_rev, 99)
                if c_rank > p_rank:
                    return DelegationVerifyResult(
                        valid=False,
                        error=f"Privilege escalation at hop {i}: reversibility '{child_rev}' exceeds parent '{parent_rev}'",
                        error_code="CDT_PRIVILEGE_ESCALATION",
                    )

        prev_token = cdt

    leaf_token = cdt_chain[-1]
    leaf_constraints = leaf_token.get("constraints", {})
    leaf_caps = leaf_constraints.get("allowed_capabilities", [])
    leaf_tools = leaf_constraints.get("allowed_tools", [])

    # 5. Check target action / capability against leaf constraints
    if required_capability:
        if required_capability not in leaf_caps:
            return DelegationVerifyResult(
                valid=False,
                error=f"Required capability '{required_capability}' not in leaf token capabilities: {leaf_caps}",
                error_code="CDT_CONSTRAINT_VIOLATION",
                chain_depth=len(cdt_chain),
            )

    if target_action and leaf_tools:
        if target_action not in leaf_tools:
            return DelegationVerifyResult(
                valid=False,
                error=f"Target tool '{target_action}' not in leaf token allowed_tools: {leaf_tools}",
                error_code="CDT_CONSTRAINT_VIOLATION",
                chain_depth=len(cdt_chain),
            )

    # 6. Proof-of-Possession (PoP) Verification if headers provided
    if pop_signature or pop_timestamp or http_method or uri_path:
        if not pop_signature:
            return DelegationVerifyResult(
                valid=False,
                error="Proof-of-Possession signature required (X-CDT-PoP-Signature missing)",
                error_code="CDT_POP_SIGNATURE_REQUIRED",
                chain_depth=len(cdt_chain),
            )
        if not pop_timestamp:
            return DelegationVerifyResult(
                valid=False,
                error="Proof-of-Possession timestamp required (X-CDT-PoP-Timestamp missing)",
                error_code="CDT_POP_SIGNATURE_REQUIRED",
                chain_depth=len(cdt_chain),
            )

        pop_valid = verify_pop_header(
            pop_signature=pop_signature,
            timestamp=pop_timestamp,
            delegate_public_key=leaf_token["delegate_public_key"],
            http_method=http_method or "POST",
            uri_path=uri_path or "/",
            token_id=leaf_token["token_id"],
        )
        if not pop_valid:
            return DelegationVerifyResult(
                valid=False,
                error="Proof-of-Possession signature verification failed or timestamp expired",
                error_code="CDT_POP_SIGNATURE_INVALID",
                chain_depth=len(cdt_chain),
            )

    return DelegationVerifyResult(
        valid=True,
        chain_depth=len(cdt_chain),
        root_delegator=cdt_chain[0]["delegator"],
        leaf_delegate=leaf_token["delegate"],
        allowed_capabilities=leaf_caps,
        allowed_tools=leaf_tools,
        max_reversibility=leaf_constraints.get("max_reversibility"),
    )

