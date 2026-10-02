"""Authentication helpers for sensitive incident data."""

import hashlib
import hmac
from dataclasses import dataclass

from fastapi import Header, HTTPException, status

from app.config import get_settings


@dataclass(frozen=True)
class AdminPrincipal:
    role: str
    key_id: str


def _configured_keys() -> list[tuple[str, str]]:
    settings = get_settings()
    return [
        (role, key)
        for role, key in (
            ("admin", settings.admin_api_key),
            ("admin", settings.previous_admin_api_key),
            ("viewer", settings.readonly_api_key),
        )
        if key
    ]


def verify_admin_key(authorization: str | None) -> AdminPrincipal:
    configured = _configured_keys()
    if not configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API authentication is not configured",
        )
    if any(len(key) < 32 for _, key in configured):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Configured API keys must contain at least 32 characters",
        )
    if len({key for _, key in configured}) != len(configured):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Configured API keys must be different",
        )
    supplied_key = ""
    if authorization and authorization.lower().startswith("bearer "):
        supplied_key = authorization[7:].strip()
    matched_role = None
    for role, key in configured:
        if hmac.compare_digest(supplied_key.encode("utf-8"), key.encode("utf-8")):
            if role == "admin" or matched_role is None:
                matched_role = role
    if not supplied_key or matched_role is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return AdminPrincipal(
        role=matched_role,
        key_id=hashlib.sha256(supplied_key.encode("utf-8")).hexdigest()[:12],
    )


def require_read_access(
    authorization: str | None = Header(default=None),
) -> AdminPrincipal:
    return verify_admin_key(authorization)


def require_admin_access(
    authorization: str | None = Header(default=None),
) -> AdminPrincipal:
    identity = verify_admin_key(authorization)
    if identity.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return identity
