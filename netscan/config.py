from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration settings."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Application
    APP_NAME: str = "NetScan"
    DEBUG: bool = False
    ENVIRONMENT: str = "development"  # development, test, or production
    SECRET_KEY: str = ""

    # Database
    DATABASE_URL: str = "sqlite:///./netscan.db"

    # Scanner Defaults
    DEFAULT_SCAN_INTERVAL_MINUTES: int = 60
    DEFAULT_MISS_THRESHOLD: int = 3
    DEFAULT_QUARANTINE_HOURS: int = 48
    NMAP_TIMEOUT_SECONDS: int = 300
    NMAP_TIMING_TEMPLATE: str = "-T4"
    TOP_TCP_PORTS: str = "80,443,22,445,3389,8080,8443,53"

    # CORS
    # Warning: ALLOWED_ORIGINS="*" is NOT permitted when DEBUG=False (production).
    # Set specific origins like: "https://example.com,http://localhost:8080"
    # The "*" wildcard is only safe when DEBUG=True (development only).
    ALLOWED_ORIGINS: str = "*"

    # Dashboard Authentication
    DASHBOARD_PASSWORD: str = "admin"

    # Webhook Defaults
    WEBHOOK_TIMEOUT_SECONDS: int = 10
    WEBHOOK_MAX_RETRIES: int = 3

    def validate_for_production(self) -> None:
        # Production safety: DEBUG=True is not allowed in production environment
        if self.ENVIRONMENT == "production" and self.DEBUG:
            raise ValueError(
                "DEBUG=True is not allowed in production environment. "
                "Set ENVIRONMENT=development or ENVIRONMENT=test, or set DEBUG=False."
            )
        if not self.DEBUG and not self.SECRET_KEY:
            raise ValueError(
                "SECRET_KEY must be set in production (DEBUG=False). "
                "Set it in your .env file or environment."
            )
        if not self.DEBUG and self.DASHBOARD_PASSWORD == "admin":
            raise ValueError(
                "DASHBOARD_PASSWORD must be changed from the default 'admin' in production "
                "(DEBUG=False). Set a strong password in your .env file or environment."
            )
        if not self.DEBUG and self.ALLOWED_ORIGINS == "*":
            raise ValueError(
                "ALLOWED_ORIGINS must not be '*' in production (DEBUG=False). "
                "Set specific origins like: 'https://example.com,http://localhost:8080'."
            )


settings = Settings()
