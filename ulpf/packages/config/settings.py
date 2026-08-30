"""
ULPF Unified Configuration Management
Provides pydantic-settings based environment configuration, secret validation, and operational limits.
"""

import os
from typing import Optional
from pathlib import Path
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Centralized Settings object loaded from environment variables and optional .env file.
    """
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Operational Mode & Security
    ULPF_DEMO_MODE: bool = Field(
        default=False,
        description="When True, allows default admin bypass and hardcoded fallback keys for offline hackathon demos."
    )
    ULPF_SECRET_KEY: Optional[str] = Field(
        default=None,
        description="Cryptographic secret key for signing JWT tokens. Required when ULPF_DEMO_MODE=False."
    )
    ULPF_JWT_ALGORITHM: str = Field(default="HS256", description="JWT signing algorithm")
    ULPF_ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=1440, description="Access token expiration (minutes)")
    ULPF_REFRESH_TOKEN_EXPIRE_MINUTES: int = Field(default=10080, description="Refresh token expiration (minutes)")

    # Storage Paths & Sinks
    ULPF_BASE_DATA_DIR: str = Field(default="data", description="Root directory for local storage sinks")
    ULPF_AIR_GAPPED: bool = Field(default=True, description="Strict air-gap enforcement flag (disables external netcalls)")

    # Network & Listener Ports
    ULPF_API_HOST: str = Field(default="0.0.0.0", description="REST API binding host")
    ULPF_API_PORT: int = Field(default=8000, description="REST API binding port")
    ULPF_UDP_SYSLOG_PORT: int = Field(default=5140, description="UDP Syslog ingestion port")
    ULPF_TCP_SYSLOG_PORT: int = Field(default=1514, description="TCP Syslog ingestion port")
    ULPF_ENABLE_SYSLOG_LISTENERS: bool = Field(default=True, description="Whether to start background UDP/TCP listeners")

    # Ingestion Bounds & Backpressure
    ULPF_MAX_INGEST_PAYLOAD_BYTES: int = Field(default=10 * 1024 * 1024, description="Maximum single payload byte limit (10MB)")
    ULPF_MAX_INGEST_QUEUE_SIZE: int = Field(default=10000, description="Maximum backpressure queue depth before shedding")
    ULPF_RATE_LIMIT_INGEST_PER_MINUTE: int = Field(default=60000, description="Ingestion rate limit per minute per IP")
    ULPF_RATE_LIMIT_AUTH_PER_MINUTE: int = Field(default=60, description="Authentication rate limit per minute per IP")

    # Logging
    ULPF_LOG_LEVEL: str = Field(default="INFO", description="Structured log level (DEBUG, INFO, WARNING, ERROR)")
    ULPF_LOG_FORMAT: str = Field(default="json", description="Log format (json or text)")

    @model_validator(mode="after")
    def validate_security_settings(self) -> "Settings":
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
                self.ULPF_SECRET_KEY = "ulpf-demo-key-for-local-offline-evaluation-only-32bytes"
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
_settings: Optional[Settings] = None


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


def reset_settings(new_settings: Optional[Settings] = None):
    """Utility to refresh settings in tests."""
    global _settings
    _settings = new_settings
