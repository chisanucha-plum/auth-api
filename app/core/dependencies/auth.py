from typing import Annotated, Optional

from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session

from app.core import security
from app.models.database.database import get_db
from app.models.database.user import User
from app.schemas.user import UserRole
from app.services.auth import AuthService


def get_user(
    db: Session = Depends(get_db),
    token: str | None = Depends(security.oauth2_scheme),
) -> Optional[User]:
    """Get the current user from the authentication token."""
    if not token:
        return None
    try:
        if token.startswith("Bearer "):
            token = token.replace("Bearer ", "")
        auth_service = AuthService(db)
        return auth_service.get_current_user(token)
    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(
            status_code=401, detail="Invalid authentication token"
        ) from error


def require_roles(roles: list[str]):
    """Reusable RBAC dependency for allowed roles."""

    def role_checker(user: User = Depends(get_user)) -> User:
        if not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        if user.role == UserRole.SUPERVISOR:
            return user
        if user.role not in roles:
            raise HTTPException(
                status_code=403,
                detail=f"You do not have permission to access this resource. Required roles: {roles}",
            )
        return user

    return role_checker


def get_guest(user: User | None = Depends(get_user)) -> User:
    """Get guest user - requires anonymous role."""
    if user is not None and (
        user.role == UserRole.ANONYMOUS or user.role == UserRole.SUPERVISOR
    ):
        return user
    raise HTTPException(status_code=401, detail="Unauthorized access - guest required")


def get_authen_user(user: User | None = Depends(get_user)) -> User:
    """Get authenticated user - requires user role."""
    if user is not None and (
        user.role == UserRole.USER or user.role == UserRole.SUPERVISOR
    ):
        return user
    raise HTTPException(
        status_code=401, detail="Unauthorized access - authentication required"
    )


def get_admin_user(user: User | None = Depends(get_user)) -> User:
    """Get admin user - requires admin role."""
    if user is not None and (
        user.role == UserRole.ADMIN or user.role == UserRole.SUPERVISOR
    ):
        return user
    raise HTTPException(status_code=403, detail="Forbidden - admin access required")


def get_any_user(user: User | None = Depends(get_user)) -> User:
    """Get any authenticated user regardless of role."""
    if user is not None:
        return user
    raise HTTPException(
        status_code=401, detail="Unauthorized access - authentication required"
    )


def get_supervisor_user(user: User = Depends(get_user)) -> User:
    """Get supervisor user - requires supervisor role only"""
    if user and user.role == UserRole.SUPERVISOR:
        return user
    raise HTTPException(
        status_code=401, detail="Forbidden - supervisor access required"
    )


def get_admin_only():
    """Admin only access"""
    return require_roles([UserRole.ADMIN])


def get_user_or_admin():
    """User or admin access"""
    return require_roles([UserRole.USER, UserRole.ADMIN])


def get_any_role():
    """Any role including anonymous"""
    return require_roles([UserRole.ANONYMOUS, UserRole.USER, UserRole.ADMIN])


UserDep = Annotated[User | None, Depends(get_user)]
GuestDep = Annotated[User, Depends(get_guest)]
AuthenticatedUserDep = Annotated[User, Depends(get_authen_user)]
AdminUserDep = Annotated[User, Depends(get_admin_user)]
AnyUserDep = Annotated[User, Depends(get_any_user)]
SupervisorDep = Annotated[User, Depends(get_supervisor_user)]
