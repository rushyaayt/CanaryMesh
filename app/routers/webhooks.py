"""Authenticated cloud-provider webhook receivers."""

import hashlib
import hmac
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, ValidationError

from app.config import get_settings
from app.database import get_db
from app.services.alert_engine import register_breach

router = APIRouter(prefix="/api/v1/webhooks", tags=["Cloud Webhooks"])


class CloudTrailEvent(BaseModel):
    model_config = ConfigDict(extra="allow")

    eventID: str
    eventTime: datetime
    eventSource: str
    sourceIPAddress: str | None = None
    eventName: str | None = None
    userAgent: str | None = None
    userIdentity: dict[str, Any]


class EventBridgePayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    account: str
    detail: CloudTrailEvent


async def _read_bounded_body(request: Request, maximum_bytes: int) -> bytes:
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > maximum_bytes:
                raise HTTPException(status_code=413, detail="Webhook payload is too large")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid Content-Length") from exc
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > maximum_bytes:
            raise HTTPException(status_code=413, detail="Webhook payload is too large")
        chunks.append(chunk)
    return b"".join(chunks)


@router.post("/aws", summary="Receive a signed AWS CloudTrail EventBridge alert")
async def aws_cloudtrail_webhook(request: Request):
    settings = get_settings()
    db = get_db()
    client_ip = request.client.host if request.client else "unknown"
    if not db.check_webhook_rate_limit(
        f"aws:{client_ip}", settings.webhook_rate_limit, settings.webhook_rate_window_seconds
    ):
        raise HTTPException(status_code=429, detail="Webhook rate limit exceeded")

    raw_body = await _read_bounded_body(request, settings.webhook_max_body_bytes)
    secret = settings.aws_webhook_secret
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AWS webhook signing is not configured",
        )
    if len(secret) < 32:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Configured AWS webhook signing secret must contain at least 32 characters",
        )
    timestamp_header = request.headers.get("x-canary-timestamp", "")
    if not timestamp_header.isascii() or not timestamp_header.isdecimal():
        raise HTTPException(status_code=401, detail="Invalid webhook timestamp")
    try:
        timestamp = int(timestamp_header)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Invalid webhook timestamp") from exc
    if abs(int(time.time()) - timestamp) > 300:
        raise HTTPException(status_code=401, detail="Webhook timestamp is outside the accepted window")

    supplied_signature = request.headers.get("x-canary-signature", "").removeprefix("sha256=")
    if len(supplied_signature) != 64 or any(
        character not in "0123456789abcdef" for character in supplied_signature
    ):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")
    expected_signature = hmac.new(
        secret.encode("utf-8"),
        timestamp_header.encode("ascii") + b"." + raw_body,
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(supplied_signature, expected_signature):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    if not settings.aws_account_id or not settings.aws_honeytoken_principal_arn:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AWS account and honeytoken principal are not configured",
        )
    try:
        payload = EventBridgePayload.model_validate_json(raw_body)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail="Invalid EventBridge payload") from exc

    event = payload.detail
    if payload.account != settings.aws_account_id:
        raise HTTPException(status_code=403, detail="EventBridge account does not match")
    principal_arn = event.userIdentity.get("arn")
    if principal_arn != settings.aws_honeytoken_principal_arn:
        raise HTTPException(status_code=403, detail="CloudTrail principal does not match")
    if not event.eventSource.endswith(".amazonaws.com") and not event.eventSource.endswith(
        ".amazonaws.com.cn"
    ):
        raise HTTPException(status_code=400, detail="Invalid CloudTrail event source")
    now = datetime.now(timezone.utc)
    event_time = event.eventTime
    if event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=timezone.utc)
    if event_time > now + timedelta(minutes=5) or event_time < now - timedelta(hours=24):
        raise HTTPException(status_code=400, detail="CloudTrail event is outside the accepted time window")
    replay_key = hashlib.sha256(f"{timestamp}:{expected_signature}".encode()).hexdigest()
    replay_expiry = datetime.fromtimestamp(timestamp + 300, timezone.utc).isoformat()
    if not db.claim_webhook_replay(replay_key, replay_expiry):
        raise HTTPException(status_code=409, detail="Webhook request was already processed")
    details = {
        "eventID": event.eventID,
        "eventTime": event_time.isoformat(),
        "eventSource": event.eventSource,
        "eventName": event.eventName,
        "sourceIPAddress": event.sourceIPAddress,
        "userAgent": event.userAgent,
    }
    await register_breach(
        token_type="AWS IAM Honeytoken",
        source_ip=event.sourceIPAddress or "Unknown",
        action=event.eventName,
        user_agent=event.userAgent or "Unknown",
        details=details,
        event_id=event.eventID,
        source="aws",
        account_id=payload.account,
        principal_arn=principal_arn,
    )
    return {"status": "alert_processed"}
