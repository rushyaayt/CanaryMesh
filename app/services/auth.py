"""Authentication helpers for sensitive incident data."""

import hmac

from fastapi import Header, HTTPException, status

from app.config import get_settings


def verify_admin_key(authorization: str | None) -> bool:
    configured_key = get_settings().admin_api_key
    if not configured_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin API authentication is not configured",
        )
    if len(configured_key) < 32:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Configured admin API key must contain at least 32 characters",
        )
    supplied_key = ""
    if authorization and authorization.lower().startswith("bearer "):
        supplied_key = authorization[7:].strip()
    if not supplied_key or not hmac.compare_digest(
        supplied_key.encode("utf-8"), configured_key.encode("utf-8")
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin API credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return True


def require_admin_access(
    authorization: str | None = Header(default=None),
) -> bool:
    return verify_admin_key(authorization)
