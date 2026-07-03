"""
Creduent Protocol SDK - Cryptographic identity verification for AI agents.
"""

from creduent.sign import generate_keys, sign
from creduent.verify import verify, VerifyResult
from creduent.register import register, RegisterResult
from creduent.attest import attest, AttestResult
from creduent.discovery import discover, DiscoveryResult, DiscoveryError
from creduent.renew import renew, RenewResult
from creduent.webhook import register_webhook, query_webhook, WebhookResult
from creduent.exceptions import (
    CreduentError,
    CreduEntError,
    VerificationError,
    RegistrationError,
    AttestationError,
)
from creduent import challenge

__all__ = [
    "generate_keys",
    "sign",
    "verify",
    "VerifyResult",
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
    "CreduentError",
    "CreduEntError",
    "VerificationError",
    "RegistrationError",
    "AttestationError",
    "challenge",
]
