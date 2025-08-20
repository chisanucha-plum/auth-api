"""
Custom exceptions for the application.
"""


class ServiceError(Exception):
    """Base exception for service layer errors"""


class ConversationNotFoundError(ServiceError):
    """Raised when a conversation is not found"""


class KnowledgeNotFoundError(ServiceError):
    """Raised when knowledge is not found"""


class ValidationError(ServiceError):
    """Raised when input validation fails"""


class ExternalServiceError(ServiceError):
    """Raised when external service (like Dify) fails"""


class NetworkError(ServiceError):
    """Raised when network operations fail"""


class TokenDecodeError(Exception):
    """Custom exception for token decoding failures."""
