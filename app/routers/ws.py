"""WebSocket endpoint for live breach events."""

import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.services.alert_engine import alert_connections

logger = logging.getLogger("canarymesh.websocket")
router = APIRouter(tags=["Live Alerts"])


@router.websocket("/api/v1/ws/alerts")
async def live_alert_feed(websocket: WebSocket):
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
