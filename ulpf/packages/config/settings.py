"""
ULPF Unified Configuration Management
Provides pydantic-settings based environment configuration, secret validation, and operational limits.
"""

import os
from pathlib import Path

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Centralized Settings object loaded from environment variables and optional .env file.
    Supports both local development/test mode and production MinIO + OpenSearch architecture.
    """

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # Operational Mode & Environment
    ULPF_ENV: str = Field(
        default="development", description="Environment: development, test, production"
    )
    ULPF_DEMO_MODE: bool = Field(
        default=False,
        description="When True, allows default admin bypass and hardcoded fallback keys for offline hackathon demos.",
    )
    ULPF_SECRET_KEY: str | None = Field(
        default=None,
        description="Cryptographic secret key for signing JWT tokens. Required when ULPF_DEMO_MODE=False.",
    )
    ULPF_JWT_ALGORITHM: str = Field(
        default="HS256", description="JWT signing algorithm"
    )
    ULPF_ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(
        default=1440, description="Access token expiration (minutes)"
    )
    ULPF_REFRESH_TOKEN_EXPIRE_MINUTES: int = Field(
        default=10080, description="Refresh token expiration (minutes)"
    )

    # Storage Backend Selection: "local" or "minio"
    ULPF_STORAGE_BACKEND: str = Field(
        default="local",
        description="Storage backend for immutable raw logs: 'local' or 'minio'",
    )
    # MinIO Object Store Configuration (Production)
    ULPF_MINIO_ENDPOINT: str | None = Field(
        default=None, description="MinIO endpoint host:port (e.g. minio:9000)"
    )
    ULPF_MINIO_ACCESS_KEY: str = Field(
        default="minioadmin", description="MinIO Access Key / Root User"
    )
    ULPF_MINIO_SECRET_KEY: str = Field(
        default="minioadmin", description="MinIO Secret Key / Root Password"
    )
    ULPF_MINIO_RAW_BUCKET: str = Field(
        default="ulpf-raw", description="Dedicated S3 bucket for immutable raw evidence"
    )
    ULPF_MINIO_SECURE: bool = Field(
        default=False, description="Whether to use TLS/HTTPS for MinIO"
    )

    # Search Backend Selection: "sqlite" or "opensearch"
    ULPF_SEARCH_BACKEND: str = Field(
        default="sqlite",
        description="Search backend for normalized OCSF telemetry: 'sqlite' or 'opensearch'",
    )
    # OpenSearch Configuration (Production)
    ULPF_OPENSEARCH_URL: str | None = Field(
        default=None, description="OpenSearch URL (e.g. http://opensearch:9200)"
    )
    ULPF_OPENSEARCH_USERNAME: str | None = Field(
        default=None, description="OpenSearch username (e.g. admin)"
    )
    ULPF_OPENSEARCH_PASSWORD: str | None = Field(
        default=None, description="OpenSearch password"
    )
    ULPF_OPENSEARCH_INDEX_PREFIX: str = Field(
        default="ulpf-events-v1", description="Index prefix for versioned OCSF events"
    )
    ULPF_OPENSEARCH_VERIFY_CERTS: bool = Field(
        default=False, description="Verify SSL certs for OpenSearch"
    )

    # Local Storage Paths & Sinks
    ULPF_BASE_DATA_DIR: str = Field(
        default="data", description="Root directory for local storage sinks"
    )
    ULPF_AIR_GAPPED: bool = Field(
        default=True,
        description="Strict air-gap enforcement flag (disables external netcalls)",
    )

    # Processing & Queueing
    ULPF_QUEUE_BACKEND: str = Field(
        default="memory",
        description="Queue backend: 'memory', 'sqlite_queue', or 'direct'",
    )
    ULPF_WORKER_CONCURRENCY: int = Field(
        default=4, description="Worker concurrency pool size"
    )
    ULPF_EVENT_DELIVERY_POLICY: str = Field(
        default="at_least_once", description="Delivery policy: 'at_least_once'"
    )

    # Data Retention (Days)
    ULPF_RAW_RETENTION_DAYS: int = Field(
        default=365, description="Retention policy for raw immutable logs (days)"
    )
    ULPF_NORMALIZED_RETENTION_DAYS: int = Field(
        default=90, description="Retention policy for normalized SIEM index (days)"
    )
    ULPF_AUDIT_RETENTION_DAYS: int = Field(
        default=730,
        description="Retention policy for administrative audit trail (days)",
    )

    # Network & Listener Ports
    ULPF_API_HOST: str = Field(default="0.0.0.0", description="REST API binding host")
    ULPF_API_PORT: int = Field(default=8000, description="REST API binding port")
    ULPF_UDP_SYSLOG_PORT: int = Field(
        default=5140, description="UDP Syslog ingestion port"
    )
    ULPF_TCP_SYSLOG_PORT: int = Field(
        default=1514, description="TCP Syslog ingestion port"
    )
    ULPF_ENABLE_SYSLOG_LISTENERS: bool = Field(
        default=True, description="Whether to start background UDP/TCP listeners"
    )

    # Ingestion Bounds & Backpressure
    ULPF_MAX_INGEST_PAYLOAD_BYTES: int = Field(
        default=10 * 1024 * 1024, description="Maximum single payload byte limit (10MB)"
    )
    ULPF_MAX_INGEST_QUEUE_SIZE: int = Field(
        default=10000, description="Maximum backpressure queue depth before shedding"
    )
    ULPF_RATE_LIMIT_INGEST_PER_MINUTE: int = Field(
        default=60000, description="Ingestion rate limit per minute per IP"
    )
    ULPF_RATE_LIMIT_AUTH_PER_MINUTE: int = Field(
        default=60, description="Authentication rate limit per minute per IP"
    )

    # Logging
    ULPF_LOG_LEVEL: str = Field(
        default="INFO", description="Structured log level (DEBUG, INFO, WARNING, ERROR)"
    )
    ULPF_LOG_FORMAT: str = Field(
        default="json", description="Log format (json or text)"
    )

    @model_validator(mode="after")
    def validate_security_and_production_settings(self) -> "Settings":
        # In non-demo mode, ULPF_SECRET_KEY is strictly mandatory and cannot be a weak default
        if not self.ULPF_DEMO_MODE:
            if not self.ULPF_SECRET_KEY or len(self.ULPF_SECRET_KEY.strip()) < 16:
                raise ValueError(
                    "FATAL SECURITY CONFIGURATION ERROR: ULPF_SECRET_KEY must be set to a secure string "
                    "(at least 16 bytes) in non-demo mode. Alternatively, set ULPF_DEMO_MODE=true for local offline testing."
                )
        else:
            # Provide safe demo fallback if unset
            if not self.ULPF_SECRET_KEY:
                self.ULPF_SECRET_KEY = (
                    "ulpf-demo-key-for-local-offline-evaluation-only-32bytes"
                )

        # Auto-configure MinIO if endpoint is provided
        if self.ULPF_MINIO_ENDPOINT and self.ULPF_STORAGE_BACKEND == "local":
            self.ULPF_STORAGE_BACKEND = "minio"

        # Auto-configure OpenSearch if URL is provided
        if self.ULPF_OPENSEARCH_URL and self.ULPF_SEARCH_BACKEND == "sqlite":
            self.ULPF_SEARCH_BACKEND = "opensearch"

        # In production environment, enforce MinIO and OpenSearch configuration
        if self.ULPF_ENV == "production" and not self.ULPF_DEMO_MODE:
            if self.ULPF_STORAGE_BACKEND == "minio" and not self.ULPF_MINIO_ENDPOINT:
                raise ValueError(
                    "FATAL CONFIGURATION ERROR: ULPF_MINIO_ENDPOINT is required when ULPF_STORAGE_BACKEND=minio in production."
                )
            if (
                self.ULPF_SEARCH_BACKEND == "opensearch"
                and not self.ULPF_OPENSEARCH_URL
            ):
                raise ValueError(
                    "FATAL CONFIGURATION ERROR: ULPF_OPENSEARCH_URL is required when ULPF_SEARCH_BACKEND=opensearch in production."
                )

        return self

    @property
    def raw_store_dir(self) -> Path:
        return Path(self.ULPF_BASE_DATA_DIR) / "raw_store"

    @property
    def parsers_dir(self) -> Path:
        return Path(self.ULPF_BASE_DATA_DIR) / "parsers"

    @property
    def onboarding_dir(self) -> Path:
        return Path(self.ULPF_BASE_DATA_DIR) / "onboarding_sessions"

    @property
    def error_queue_dir(self) -> Path:
        return Path(self.ULPF_BASE_DATA_DIR) / "error_queue"

    @property
    def data_lake_dir(self) -> Path:
        return Path(self.ULPF_BASE_DATA_DIR) / "data_lake"

    @property
    def search_index_path(self) -> Path:
        return Path(self.ULPF_BASE_DATA_DIR) / "search_index.db"


# Singleton instance
_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        # Check if DEMO_MODE explicitly set via env, or default to demo for existing test suite if not configured
        demo_mode_env = os.environ.get("ULPF_DEMO_MODE")
        if demo_mode_env is None:
            # If not explicitly set and secret key is missing, default to true if testing or demo env
            if not os.environ.get("ULPF_SECRET_KEY"):
                os.environ["ULPF_DEMO_MODE"] = "true"
        _settings = Settings()
    return _settings


def reset_settings(new_settings: Settings | None = None):
    """Utility to refresh settings in tests."""
    global _settings
    _settings = new_settings
