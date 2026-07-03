"""
Creduent Python SDK custom exceptions.
"""


class CreduentError(Exception):
    """Base exception for all Creduent errors."""

    pass


# Alias for backward compatibility
CreduEntError = CreduentError


class VerificationError(CreduentError):
    """Exception raised when identity or cryptographic verification fails."""

    pass


class RegistrationError(CreduentError):
    """Exception raised when agent registration with the registry fails."""

    pass


class AttestationError(CreduentError):
    """Exception raised when querying or validating registry attestations fails."""

    pass
