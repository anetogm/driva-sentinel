import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.api.v1.auth import router as auth_router
from app.api.v1.health import router as health_router
from app.api.v1.scans import router as scans_router
from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger, set_correlation_id
from app.core.security import get_client_ip
from app.core.telemetry import metrics
from app.db.base import Base
from app.db.session import engine

configure_logging()
logger = get_logger("main")

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("application_startup")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("database_initialized")
    yield
    logger.info("application_shutdown")
    await engine.dispose()


limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[f"{settings.RATE_LIMIT_PER_MINUTE} per minute"],
)

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="KindMelody Security Scanner API - Enterprise-grade website security analysis",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID"],
)
app.add_middleware(GZipMiddleware, minimum_size=1000)


@app.middleware("http")
async def correlation_id_middleware(request: Request, call_next):
    cid = request.headers.get("x-request-id") or request.headers.get("x-correlation-id")
    cid = set_correlation_id(cid)
    request.state.correlation_id = cid

    start = time.perf_counter()
    response = await call_next(request)
    elapsed = time.perf_counter() - start

    response.headers["x-request-id"] = cid
    metrics.observe("http_request_duration_seconds", elapsed, {"path": request.url.path})
    metrics.increment("http_requests_total", 1, {"path": request.url.path, "method": request.method})

    logger.info(
        "request_completed",
        method=request.method,
        path=request.url.path,
        status=response.status_code,
        elapsed_ms=round(elapsed * 1000, 2),
        correlation_id=cid,
        client_ip=get_client_ip(request),
    )

    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(
        "unhandled_exception",
        error=str(exc),
        error_type=type(exc).__name__,
        path=request.url.path,
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error", "correlation_id": request.state.correlation_id},
    )


v1_prefix = settings.API_V1_PREFIX
app.include_router(auth_router, prefix=f"{v1_prefix}/auth")
app.include_router(scans_router, prefix=f"{v1_prefix}/scans")
app.include_router(health_router, prefix=f"{v1_prefix}/health")


@app.get("/")
async def root():
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "docs": "/api/docs",
    }
