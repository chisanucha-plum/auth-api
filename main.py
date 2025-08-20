import logging
import time

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from structlog import get_logger, wrap_logger

from app.configuration import Configuration
from app.routers.router import get_router

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = wrap_logger(get_logger(__name__))
config = Configuration.get_config()
app = FastAPI(
    title=config.application.title,
    version=config.application.version,
    redirect_slashes=config.application.redirect_slashes,
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    # NOTE: maybe track through system later
    request_id = request.headers.get("X-Request-ID", "N/A")

    response = await call_next(request)

    duration = time.time() - start_time
    log.info(
        "http_request_completed",
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
        duration_ms=round(duration * 1000, 2),
        request_id=request_id,
    )
    return response


log.info(f"CORS SETTINGS: {config.cors}")
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.cors.allow_origins,
    allow_credentials=config.cors.allow_credentials,
    allow_methods=config.cors.allow_methods,
    allow_headers=config.cors.allow_headers,
)

app.include_router(get_router())

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app", host="localhost", port=8011, reload=True, proxy_headers=True
    )
