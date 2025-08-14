from typing import Optional, List, Dict
from datetime import datetime
from app.models.user import User, UserCreate, UserLogin
from app.core.security import get_password_hash, verify_password
from app.core.exceptions import UserAlreadyExistsException, UserNotFoundException, InvalidCredentialsException

class UserService:
    """Service for user-related operations."""
    
    def __init__(self):
        # In a real application, this would be a database
        # For now, we'll use an in-memory store
        self._users: Dict[int, User] = {}
        self._next_id = 1
        self._username_index: Dict[str, int] = {}
        self._email_index: Dict[str, int] = {}
    
    def create_user(self, user_data: UserCreate) -> User:
        """Create a new user."""
        # Check if user already exists
        if user_data.username in self._username_index:
            raise UserAlreadyExistsException()
        
        if user_data.email in self._email_index:
            raise UserAlreadyExistsException()
        
        # Hash password
        hashed_password = get_password_hash(user_data.password)
        
        # Create user
        user = User(
            id=self._next_id,
            username=user_data.username,
            email=user_data.email,
            full_name=user_data.full_name,
            hashed_password=hashed_password,
            is_active=True,
            created_at=datetime.utcnow()
        )
        
        # Store user
        self._users[self._next_id] = user
        self._username_index[user_data.username] = self._next_id
        self._email_index[user_data.email] = self._next_id
        self._next_id += 1
        
        return user
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate a user with username and password."""
        user = self.get_user_by_username(username)
        if not user:
            return None
        
        if not verify_password(password, user.hashed_password):
            return None
        
        return user
    
    def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username."""
        user_id = self._username_index.get(username)
        if user_id is None:
            return None
        return self._users.get(user_id)
    
    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID."""
        return self._users.get(user_id)
    
    def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        user_id = self._email_index.get(email)
        if user_id is None:
            return None
        return self._users.get(user_id)
    
    def get_all_users(self) -> List[User]:
        """Get all users."""
        return list(self._users.values())
    
    def update_user(self, user_id: int, update_data: dict) -> Optional[User]:
        """Update user data."""
        user = self._users.get(user_id)
        if not user:
            raise UserNotFoundException()
        
        # Update allowed fields
        for field, value in update_data.items():
            if hasattr(user, field) and field not in ['id', 'created_at', 'hashed_password']:
                setattr(user, field, value)
        
        return user
    
    def delete_user(self, user_id: int) -> bool:
        """Delete a user."""
        user = self._users.get(user_id)
        if not user:
            raise UserNotFoundException()
        
        # Remove from indices
        del self._username_index[user.username]
        del self._email_index[user.email]
        del self._users[user_id]
        
        return True
