from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime

class UserBase(BaseModel):
    """Base user model with common fields."""
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    full_name: Optional[str] = None

class UserCreate(UserBase):
    """Model for user registration."""
    password: str = Field(..., min_length=6, max_length=100)

class UserLogin(BaseModel):
    """Model for user login."""
    username: str
    password: str

class UserResponse(UserBase):
    """Model for user response (excludes sensitive data)."""
    id: int
    is_active: bool
    created_at: datetime
    
    class Config:
        from_attributes = True

class User(UserBase):
    """Full user model (for internal use)."""
    id: int
    hashed_password: str
    is_active: bool = True
    created_at: datetime
    
    class Config:
        from_attributes = True

class Token(BaseModel):
    """Model for JWT token response."""
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    """Model for token data."""
    username: Optional[str] = None
