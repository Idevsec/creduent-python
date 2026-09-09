"""
Creduent Protocol SDK - Cryptographic identity verification for AI agents.
"""

from creduent.sign import generate_keys, sign
from creduent.verify import verify, VerifyResult, clear_verification_cache, invalidate_agent_cache
from creduent.register import register, RegisterResult
from creduent.attest import attest, AttestResult
from creduent.discovery import discover, DiscoveryResult, DiscoveryError
from creduent.renew import renew, RenewResult
from creduent.webhook import register_webhook, query_webhook, WebhookResult, verify_webhook_signature
from creduent.exceptions import (
    CreduentError,
    CreduEntError,
    VerificationError,
    RegistrationError,
    AttestationError,
)
from creduent import challenge

from creduent.provenance import ProvenanceGuard, normalize_reversibility_class, ReversibilityClass
from creduent.ledger import LedgerChainVerifier, LedgerIntegrityError, LedgerClient
from creduent.did import agent_to_did, did_to_agent, agent_to_did_document

__all__ = [
    "generate_keys",
    "sign",
    "verify",
    "VerifyResult",
    "clear_verification_cache",
    "invalidate_agent_cache",
    "register",
    "RegisterResult",
    "attest",
    "AttestResult",
    "discover",
    "DiscoveryResult",
    "DiscoveryError",
    "renew",
    "RenewResult",
    "register_webhook",
    "query_webhook",
    "WebhookResult",
    "verify_webhook_signature",
    "CreduentError",
    "CreduEntError",
    "VerificationError",
    "RegistrationError",
    "AttestationError",
    "challenge",
    "ProvenanceGuard",
    "normalize_reversibility_class",
    "ReversibilityClass",
    "LedgerChainVerifier",
    "LedgerIntegrityError",
    "LedgerClient",
    "agent_to_did",
    "did_to_agent",
    "agent_to_did_document",
]



