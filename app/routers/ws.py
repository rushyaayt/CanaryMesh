"""WebSocket endpoint for live breach events."""

import logging

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect

from app.services.alert_engine import alert_connections
from app.services.auth import verify_admin_key

logger = logging.getLogger("canarymesh.websocket")
router = APIRouter(tags=["Live Alerts"])


@router.websocket("/api/v1/ws/alerts")
async def live_alert_feed(websocket: WebSocket):
    protocols = websocket.scope.get("subprotocols", [])
    credential = next(
        (
            protocol.removeprefix("canarymesh-auth.")
            for protocol in protocols
            if protocol.startswith("canarymesh-auth.")
        ),
        None,
    )
    if not credential:
        authorization = websocket.headers.get("authorization", "")
        if authorization.lower().startswith("bearer "):
            credential = authorization[7:].strip()
    try:
        verify_admin_key(f"Bearer {credential}" if credential else None)
    except HTTPException as exc:
        await websocket.close(code=1013 if exc.status_code == 503 else 1008)
        return
    await alert_connections.connect(websocket)
    try:
        while True:
            # Keep the connection alive and detect clients that have disconnected.
            await websocket.receive_text()
    except WebSocketDisconnect:
        alert_connections.disconnect(websocket)
    except RuntimeError:
        logger.debug("WebSocket client disconnected")
        alert_connections.disconnect(websocket)
