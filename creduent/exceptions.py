"""
Creduent Python SDK custom exceptions.
"""

class CreduEntError(Exception):
    """Base exception for all Creduent errors."""
    pass

class VerificationError(CreduEntError):
    """Exception raised when identity or cryptographic verification fails."""
    pass

class RegistrationError(CreduEntError):
    """Exception raised when agent registration with the registry fails."""
    pass

class AttestationError(CreduEntError):
    """Exception raised when querying or validating registry attestations fails."""
    pass
