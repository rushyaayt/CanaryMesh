"""Authenticated cloud-provider webhook receivers."""

import hmac
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict

from app.config import get_settings
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


@router.post("/aws", summary="Receive an AWS CloudTrail EventBridge alert")
async def aws_cloudtrail_webhook(
    payload: EventBridgePayload,
    x_canary_webhook_secret: str | None = Header(default=None),
):
    configured_secret = get_settings().aws_webhook_secret
    settings = get_settings()
    if not configured_secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AWS webhook authentication is not configured",
        )
    if len(configured_secret) < 32:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Configured AWS webhook secret must contain at least 32 characters",
        )
    if not x_canary_webhook_secret or not hmac.compare_digest(
        x_canary_webhook_secret.encode("utf-8"), configured_secret.encode("utf-8")
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook authentication",
        )
    if not settings.aws_account_id or not settings.aws_honeytoken_principal_arn:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AWS account and honeytoken principal are not configured",
        )

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
