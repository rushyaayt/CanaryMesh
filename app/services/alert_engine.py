"""Persistence and fan-out for standalone decoy breach events."""

import logging
import uuid
from typing import Any

from fastapi import BackgroundTasks, WebSocket
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


async def register_breach(
    token_type: str,
    source_ip: str,
    user_agent: str = "Unknown",
    path: str | None = None,
    action: str | None = None,
    details: dict[str, Any] | None = None,
    background_tasks: BackgroundTasks | None = None,
) -> dict[str, Any]:
    breach = get_db().record_breach(
        breach_id=f"breach_{uuid.uuid4().hex[:12]}",
        token_type=token_type,
        source_ip=source_ip or "Unknown",
        user_agent=user_agent or "Unknown",
        path=path,
        action=action,
        details=details,
    )
    await alert_connections.broadcast(breach)

    webhook_url = get_settings().default_webhook_url
    if webhook_url:
        if background_tasks is not None:
            background_tasks.add_task(send_webhook_alert, webhook_url, breach)
        else:
            await send_webhook_alert(webhook_url, breach)
    return breach
