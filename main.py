from fastapi import FastAPI
from app.router import auth
from app.core.config import settings

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    debug=settings.debug
)

# Include routers
app.include_router(auth.router, prefix="/auth", tags=["authentication"])

@app.get("/")
async def root():
    return {"message": "Auth API is running", "version": settings.app_version}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}
