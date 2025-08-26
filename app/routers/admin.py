from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from structlog import get_logger

from app.core.dependencies.auth import get_admin_only
from app.models.database.database import get_db
from app.models.database.user import User
from app.services.auth import AuthService

logger = get_logger(__name__)

router = APIRouter(tags=["admin"])


class PromoteUserRequest(BaseModel):
    email: str


@router.post("/promote/{user_id}", status_code=status.HTTP_200_OK)
def promote_user_to_admin(
    user_id: str,
    db: Annotated[Session, Depends(get_db)],
    admin: Annotated[User, Depends(get_admin_only)],
):
    """Promote an existing user to admin role. Requires admin privileges."""
    try:
        auth_service = AuthService(db)
        promoted_user = auth_service.promote_user_to_admin(user_id)
        return {
            "message": "User promoted to admin successfully",
            "user_id": promoted_user.id,
            "email": promoted_user.email,
            "role": promoted_user.role,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Error promoting user to admin")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to promote user to admin",
        ) from e


@router.post("/promote-by-email", status_code=status.HTTP_200_OK)
def promote_user_by_email_to_admin(
    request: PromoteUserRequest,
    db: Annotated[Session, Depends(get_db)],
    admin: Annotated[User, Depends(get_admin_only)],
):
    """Promote an existing user to admin role by email. Requires admin privileges."""
    try:
        auth_service = AuthService(db)
        promoted_user = auth_service.promote_user_by_email_to_admin(request.email)
        return {
            "message": "User promoted to admin successfully",
            "user_id": promoted_user.id,
            "email": promoted_user.email,
            "role": promoted_user.role,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Error promoting user to admin")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to promote user to admin",
        ) from e
