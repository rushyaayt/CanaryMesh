"""CanaryMesh Configuration Module"""

import os
from functools import lru_cache
from typing import Optional
from pydantic import BaseModel, Field


class Settings(BaseModel):
    app_name: str = "CanaryMesh"
    version: str = "0.1.0"
    debug: bool = Field(default_factory=lambda: os.getenv("CANARY_DEBUG", "false").lower() == "true")

    # Networking & URLs
    host: str = Field(default_factory=lambda: os.getenv("CANARY_HOST", "0.0.0.0"))
    port: int = Field(default_factory=lambda: int(os.getenv("CANARY_PORT", "8000")))
    public_url: str = Field(default_factory=lambda: os.getenv("CANARY_PUBLIC_URL", "http://localhost:8000").rstrip("/"))

    # Cryptographic Secret for Honeytoken Signatures
    secret_key: str = Field(
        default_factory=lambda: os.getenv(
            "CANARY_SECRET_KEY", "canarymesh-super-secure-ephemeral-deception-key-v1"
        )
    )

    # SQLite Database File Path
    database_path: str = Field(default_factory=lambda: os.getenv("CANARY_DATABASE_PATH", "canarymesh.db"))

    # Global Default Alert Webhook (Slack / Discord / SIEM)
    default_webhook_url: Optional[str] = Field(
        default_factory=lambda: os.getenv("CANARY_DEFAULT_WEBHOOK_URL", None)
    )
    aws_webhook_secret: Optional[str] = Field(
        default_factory=lambda: os.getenv("CANARY_AWS_WEBHOOK_SECRET", None)
    )
    admin_api_key: Optional[str] = Field(
        default_factory=lambda: os.getenv("CANARY_ADMIN_API_KEY", None)
    )
    previous_admin_api_key: Optional[str] = Field(
        default_factory=lambda: os.getenv("CANARY_PREVIOUS_ADMIN_API_KEY", None)
    )
    readonly_api_key: Optional[str] = Field(
        default_factory=lambda: os.getenv("CANARY_READONLY_API_KEY", None)
    )
    aws_account_id: Optional[str] = Field(
        default_factory=lambda: os.getenv("CANARY_AWS_ACCOUNT_ID", None)
    )
    aws_honeytoken_principal_arn: Optional[str] = Field(
        default_factory=lambda: os.getenv("CANARY_AWS_PRINCIPAL_ARN", None)
    )
    webhook_allowed_hosts: list[str] = Field(
        default_factory=lambda: [
            host.strip().lower()
            for host in os.getenv("CANARY_WEBHOOK_ALLOWED_HOSTS", "").split(",")
            if host.strip()
        ]
    )
    redis_url: Optional[str] = Field(default_factory=lambda: os.getenv("CANARY_REDIS_URL") or None)
    retention_days: int = Field(
        default_factory=lambda: max(0, int(os.getenv("CANARY_RETENTION_DAYS", "0")))
    )
    webhook_rate_limit: int = Field(
        default_factory=lambda: max(1, int(os.getenv("CANARY_WEBHOOK_RATE_LIMIT", "60")))
    )
    webhook_rate_window_seconds: int = Field(
        default_factory=lambda: max(1, int(os.getenv("CANARY_WEBHOOK_RATE_WINDOW_SECONDS", "60")))
    )
    webhook_max_body_bytes: int = Field(
        default_factory=lambda: max(1024, int(os.getenv("CANARY_WEBHOOK_MAX_BODY_BYTES", "65536")))
    )

    # Forensics & Network Telemetry
    geoip_enabled: bool = Field(
        default_factory=lambda: os.getenv("CANARY_GEOIP_ENABLED", "true").lower() == "true"
    )
    trust_proxy_headers: bool = Field(
        default_factory=lambda: os.getenv("CANARY_TRUST_PROXY_HEADERS", "false").lower() == "true"
    )

    # Delay added to decoy responses to simulate authentic server processing (ms)
    decoy_delay_ms: int = Field(default_factory=lambda: int(os.getenv("CANARY_DECOY_DELAY_MS", "80")))


@lru_cache()
def get_settings() -> Settings:
    return Settings()
