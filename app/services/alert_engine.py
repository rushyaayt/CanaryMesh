"""Persistence and fan-out for standalone decoy breach events."""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import WebSocket
from starlette.websockets import WebSocketDisconnect

from app.config import get_settings
from app.database import get_db
from app.services.notifier import send_webhook_alert
from redis.exceptions import RedisError

logger = logging.getLogger("canarymesh.alert_engine")
ALERT_CHANNEL = "canarymesh:alerts"


class AlertConnections:
    def __init__(self):
        self.active: set[WebSocket] = set()
        self.instance_id = uuid.uuid4().hex
        self.redis = None
        self.redis_task: asyncio.Task | None = None
        self.redis_ready = asyncio.Event()

    async def start_redis(self, redis_url: str) -> None:
        from redis.asyncio import Redis

        self.redis = Redis.from_url(
            redis_url, decode_responses=True, socket_connect_timeout=2
        )
        try:
            await self.redis.ping()
            self.redis_task = asyncio.create_task(self._listen_for_remote_alerts())
            await asyncio.wait_for(self.redis_ready.wait(), timeout=2)
        except (RedisError, asyncio.TimeoutError) as exc:
            await self.stop_redis()
            raise RedisError("Redis alert subscription could not start") from exc

    async def stop_redis(self) -> None:
        if self.redis_task:
            self.redis_task.cancel()
            try:
                await self.redis_task
            except asyncio.CancelledError:
                pass
            self.redis_task = None
        if self.redis:
            try:
                await self.redis.aclose()
            except RedisError as exc:
                logger.warning("Redis client cleanup failed (%s)", type(exc).__name__)
            finally:
                self.redis = None
        self.redis_ready.clear()

    async def _listen_for_remote_alerts(self) -> None:
        while self.redis:
            pubsub = self.redis.pubsub()
            try:
                await pubsub.subscribe(ALERT_CHANNEL)
                self.redis_ready.set()
                async for message in pubsub.listen():
                    if message.get("type") != "message":
                        continue
                    envelope = json.loads(message["data"])
                    if envelope.get("origin") != self.instance_id:
                        await self._broadcast_local(envelope["event"])
            except asyncio.CancelledError:
                raise
            except (RedisError, ValueError, KeyError) as exc:
                logger.warning("Redis alert subscription failed (%s)", type(exc).__name__)
                await asyncio.sleep(1)
            finally:
                try:
                    await pubsub.aclose()
                except RedisError as exc:
                    logger.debug("Redis Pub/Sub cleanup failed (%s)", type(exc).__name__)

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active.add(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self.active.discard(websocket)

    async def broadcast(self, breach: dict[str, Any]) -> None:
        await self._broadcast_local(breach)
        if self.redis:
            try:
                await self.redis.publish(
                    ALERT_CHANNEL,
                    json.dumps({"origin": self.instance_id, "event": breach}),
                )
            except RedisError as exc:
                logger.warning("Redis alert publish failed (%s)", type(exc).__name__)

    async def _broadcast_local(self, breach: dict[str, Any]) -> None:
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
    webhook_url = get_settings().default_webhook_url
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
        enqueue_notification=bool(webhook_url),
    )
    if breach.pop("_duplicate", False):
        return breach
    await alert_connections.broadcast(breach)

    return breach


async def process_notification(notification_id: int | None = None) -> None:
    db = get_db()
    worker_id = uuid.uuid4().hex
    notification = db.claim_notification(worker_id, notification_id=notification_id)
    if not notification:
        return
    await _deliver_claimed_notification(db, notification, worker_id)


async def _deliver_claimed_notification(
    db, notification: dict[str, Any], worker_id: str
) -> None:
    event = db.get_event(notification["event_id"])
    webhook_url = db.get_event_webhook_url(notification["event_id"])
    webhook_url = webhook_url or get_settings().default_webhook_url
    if not event:
        db.update_notification(
            notification["id"],
            "failed",
            notification["attempts"],
            "Incident event is unavailable",
            worker_id=worker_id,
        )
        return
    if not webhook_url:
        db.update_notification(
            notification["id"],
            "failed",
            notification["attempts"],
            "No webhook destination is configured",
            worker_id=worker_id,
        )
        return

    attempts = notification["attempts"] + 1
    db.update_notification(
        notification["id"],
        "processing",
        attempts,
        worker_id=worker_id,
    )
    alert_payload = event
    if "client_ip" in event:
        alert_payload = {
            **event,
            "source_ip": event["client_ip"],
            "path": event["request_path"],
            "action": event["http_method"],
        }
    if await send_webhook_alert(webhook_url, alert_payload):
        db.update_notification(notification["id"], "sent", attempts, worker_id=worker_id)
        db.mark_alert_notified(notification["event_id"], True)
        return

    if attempts >= 3:
        db.update_notification(
            notification["id"],
            "failed",
            attempts,
            "Delivery failed after 3 attempts",
            worker_id=worker_id,
        )
        return
    retry_at = datetime.now(timezone.utc) + timedelta(seconds=2 ** (attempts + 1))
    db.update_notification(
        notification["id"],
        "pending",
        attempts,
        "Webhook delivery failed",
        worker_id=worker_id,
        next_attempt_at=retry_at.isoformat(),
    )


async def notification_worker() -> None:
    """Claim due outbox entries with leases and bounded retry scheduling."""
    db = get_db()
    while True:
        pending = db.claim_notification(uuid.uuid4().hex)
        if pending:
            await _deliver_claimed_notification(
                db, pending, pending["lease_owner"]
            )
        else:
            await asyncio.sleep(0.5)
