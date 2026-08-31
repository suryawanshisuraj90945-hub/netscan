import json
import logging
import shutil
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from sqlalchemy import text
from netscan.api.v1.router import api_v1_router
from netscan.config import settings
from netscan.db import init_db, engine
from netscan.limiter import limiter
from netscan.services.scheduler_service import scheduler
from netscan.web.auth import DashboardAuthMiddleware
from netscan.web.views import web_router


class JsonFormatter(logging.Formatter):
    """JSON log formatter with support for structured fields via extra={...}."""

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add extra fields from record.__dict__ that are not standard logging attributes
        standard_attrs = {
            "name", "msg", "args", "created", "filename", "funcName",
            "levelname", "levelno", "lineno", "module", "msecs",
            "message", "pathname", "process", "processName",
            "relativeCreated", "thread", "threadName", "exc_info",
            "exc_text", "stack_info",
        }

        for key, value in record.__dict__.items():
            if key not in standard_attrs:
                try:
                    json.dumps(value)
                    log_data[key] = value
                except (TypeError, ValueError):
                    log_data[key] = str(value)

        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data, ensure_ascii=False)


def configure_logging() -> None:
    """Configure structured JSON logging for production, human-readable for development."""
    handler = logging.StreamHandler(sys.stdout)
    if settings.DEBUG:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s"
        ))
    else:
        handler.setFormatter(JsonFormatter())

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.DEBUG if settings.DEBUG else logging.INFO)


configure_logging()
logger = logging.getLogger("netscan")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.validate_for_production()
    logger.info("Initializing NetScan database...")
    init_db()
    logger.info("Starting NetScan scheduler...")
    scheduler.start()
    yield
    logger.info("Stopping NetScan scheduler...")
    scheduler.shutdown()


app = FastAPI(
    title="NetScan API",
    description="Production-Grade IP Discovery and Availability Platform",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.ALLOWED_ORIGINS.split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(DashboardAuthMiddleware)
app.add_middleware(SessionMiddleware, secret_key=settings.SECRET_KEY)

# Mount Routers
app.include_router(api_v1_router)
app.include_router(web_router)


@app.get("/health", tags=["System"])
@limiter.exempt
def health_check(request: Request):
    checks = {"database": "ok", "nmap": "ok"}
    status_code = "healthy"

    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        checks["database"] = "unavailable"
        status_code = "degraded"

    if not shutil.which("nmap"):
        checks["nmap"] = "not found"
        status_code = "degraded"

    return {"status": status_code, "service": "NetScan", "version": "0.1.0", "checks": checks}
