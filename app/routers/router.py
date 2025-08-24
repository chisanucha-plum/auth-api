from fastapi import APIRouter

from app.routers.admin import router as admin_router
from app.routers.user import router as user_router


def get_router():
    router = APIRouter()

    router.include_router(user_router, prefix="/user")
    router.include_router(admin_router, prefix="/admin")
    return router
