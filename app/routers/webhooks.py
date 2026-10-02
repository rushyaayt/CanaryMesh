"""Authenticated cloud-provider webhook receivers."""

import hmac

from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict

from app.config import get_settings
from app.services.alert_engine import register_breach

router = APIRouter(prefix="/api/v1/webhooks", tags=["Cloud Webhooks"])


class CloudTrailEvent(BaseModel):
    model_config = ConfigDict(extra="allow")

    sourceIPAddress: str | None = None
    eventName: str | None = None
    userAgent: str | None = None


class EventBridgePayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    detail: CloudTrailEvent


@router.post("/aws", summary="Receive an AWS CloudTrail EventBridge alert")
async def aws_cloudtrail_webhook(
    payload: EventBridgePayload,
    background_tasks: BackgroundTasks,
    x_canary_webhook_secret: str | None = Header(default=None),
):
    configured_secret = get_settings().aws_webhook_secret
    if not configured_secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AWS webhook authentication is not configured",
        )
    if not x_canary_webhook_secret or not hmac.compare_digest(
        x_canary_webhook_secret, configured_secret
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook authentication",
        )

    event = payload.detail
    await register_breach(
        token_type="AWS IAM Honeytoken",
        source_ip=event.sourceIPAddress or "Unknown",
        action=event.eventName,
        user_agent=event.userAgent or "Unknown",
        details=payload.model_dump(exclude_none=True),
        background_tasks=background_tasks,
    )
    return {"status": "alert_processed"}
