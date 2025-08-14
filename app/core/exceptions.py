from fastapi import HTTPException, status

class AuthException(HTTPException):
    """Base authentication exception."""
    pass

class InvalidCredentialsException(AuthException):
    """Raised when credentials are invalid."""
    def __init__(self):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )

class TokenExpiredException(AuthException):
    """Raised when token has expired."""
    def __init__(self):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"}
        )

class UserAlreadyExistsException(AuthException):
    """Raised when trying to register a user that already exists."""
    def __init__(self):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already exists"
        )

class UserNotFoundException(AuthException):
    """Raised when user is not found."""
    def __init__(self):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
