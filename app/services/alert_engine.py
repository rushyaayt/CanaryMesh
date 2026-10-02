"""Persistence and fan-out for standalone decoy breach events."""

import asyncio
import logging
import uuid
from typing import Any

from fastapi import WebSocket
from starlette.websockets import WebSocketDisconnect

from app.config import get_settings
from app.database import get_db
from app.services.notifier import send_webhook_alert

logger = logging.getLogger("canarymesh.alert_engine")


class AlertConnections:
    def __init__(self):
        self.active: set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active.add(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self.active.discard(websocket)

    async def broadcast(self, breach: dict[str, Any]) -> None:
        disconnected = []
        for websocket in tuple(self.active):
            try:
                await websocket.send_json(breach)
            except (RuntimeError, OSError, WebSocketDisconnect):
                disconnected.append(websocket)
        for websocket in disconnected:
            self.disconnect(websocket)


alert_connections = AlertConnections()


async def broadcast_alert(alert: dict[str, Any]) -> None:
    await alert_connections.broadcast(
        {
            "id": alert["id"],
            "timestamp": alert["timestamp"],
            "token_type": alert["token_type"],
            "source": "token",
            "source_ip": alert["client_ip"],
            "user_agent": alert["user_agent"],
            "path": alert["request_path"],
            "action": alert["http_method"],
            "severity": alert["severity"],
            "token_id": alert["token_id"],
            "token_label": alert["token_label"],
            "event_id": None,
            "account_id": None,
            "principal_arn": None,
            "details": alert["geo_location"],
        }
    )


async def register_breach(
    token_type: str,
    source_ip: str,
    user_agent: str = "Unknown",
    path: str | None = None,
    action: str | None = None,
    details: dict[str, Any] | None = None,
    event_id: str | None = None,
    source: str = "decoy",
    account_id: str | None = None,
    principal_arn: str | None = None,
) -> dict[str, Any]:
    breach = get_db().record_breach(
        breach_id=f"breach_{uuid.uuid4().hex[:12]}",
        token_type=token_type,
        source_ip=source_ip or "Unknown",
        user_agent=user_agent or "Unknown",
        path=path,
        action=action,
        details=details,
        event_id=event_id,
        source=source,
        account_id=account_id,
        principal_arn=principal_arn,
    )
    if breach.pop("_duplicate", False):
        return breach
    await alert_connections.broadcast(breach)

    webhook_url = get_settings().default_webhook_url
    if webhook_url:
        get_db().create_notification(breach["id"])
    return breach


async def process_notification(notification_id: int) -> None:
    db = get_db()
    notification = db.get_notification(notification_id)
    if not notification or notification["status"] != "pending":
        return
    event = db.get_event(notification["event_id"])
    webhook_url = db.get_event_webhook_url(notification["event_id"])
    webhook_url = webhook_url or get_settings().default_webhook_url
    if not event:
        db.update_notification(
            notification_id,
            "failed",
            notification["attempts"],
            "Incident event is unavailable",
        )
        return
    if not webhook_url:
        return

    attempts = notification["attempts"]
    delays = (0, 1, 2)
    while attempts < len(delays):
        delay = delays[attempts]
        if delay:
            await asyncio.sleep(delay)
        attempts += 1
        db.update_notification(notification_id, "pending", attempts, "Delivery attempt failed")
        alert_payload = event
        if "client_ip" in event:
            alert_payload = {
                **event,
                "source_ip": event["client_ip"],
                "path": event["request_path"],
                "action": event["http_method"],
            }
        if await send_webhook_alert(webhook_url, alert_payload):
            db.update_notification(notification_id, "sent", attempts)
            db.mark_alert_notified(notification["event_id"], True)
            return
    db.update_notification(notification_id, "failed", attempts, "Delivery failed after 3 attempts")


async def notification_worker() -> None:
    """Recover deliveries left pending after a process restart."""
    db = get_db()
    while True:
        pending = db.list_pending_notifications(limit=25)
        if not pending:
            await asyncio.sleep(1)
            continue
        notification = pending[0]
        has_token_webhook = db.get_event_webhook_url(notification["event_id"])
        if not has_token_webhook and not get_settings().default_webhook_url:
            await asyncio.sleep(1)
            continue
        await process_notification(notification["id"])
