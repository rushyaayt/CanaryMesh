"""Historical standalone breach event API."""

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse

from app.database import get_db
from app.services.auth import AdminPrincipal, require_admin_access, require_read_access

router = APIRouter(prefix="/api/v1", tags=["Alerts & Forensics"])


def _utc_datetime(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _utc_iso(value: datetime | None) -> str | None:
    normalized = _utc_datetime(value)
    return normalized.isoformat() if normalized else None


def _safe_csv_value(value: Any) -> Any:
    if isinstance(value, str) and value.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


@router.get("/breaches", summary="List persisted standalone breach events")
def list_breaches(
    limit: int = Query(50, ge=1, le=200),
    _authorized: AdminPrincipal = Depends(require_read_access),
) -> list[dict[str, Any]]:
    return get_db().list_breaches(limit=limit)


@router.get("/events", summary="Search the unified incident event history")
def list_events(
    limit: int = Query(100, ge=1, le=500),
    token_id: str | None = None,
    token_type: str | None = None,
    source_ip: str | None = None,
    severity: str | None = None,
    source: str | None = Query(default=None, pattern="^(token|decoy|aws)$"),
    since: datetime | None = None,
    until: datetime | None = None,
    _authorized: AdminPrincipal = Depends(require_read_access),
) -> list[dict[str, Any]]:
    since_utc = _utc_datetime(since)
    until_utc = _utc_datetime(until)
    if since_utc and until_utc and since_utc > until_utc:
        raise HTTPException(status_code=400, detail="'since' must not be later than 'until'")
    return get_db().list_events(
        limit=limit,
        token_id=token_id,
        token_type=token_type,
        source_ip=source_ip,
        severity=severity,
        source=source,
        since=_utc_iso(since),
        until=_utc_iso(until),
    )


@router.get("/events/export", summary="Export filtered incident events as CSV")
def export_events(
    limit: int = Query(500, ge=1, le=5000),
    token_id: str | None = None,
    token_type: str | None = None,
    source_ip: str | None = None,
    severity: str | None = None,
    source: str | None = Query(default=None, pattern="^(token|decoy|aws)$"),
    since: datetime | None = None,
    until: datetime | None = None,
    _authorized: AdminPrincipal = Depends(require_read_access),
):
    from csv import DictWriter
    from io import StringIO

    since_utc = _utc_datetime(since)
    until_utc = _utc_datetime(until)
    if since_utc and until_utc and since_utc > until_utc:
        raise HTTPException(status_code=400, detail="'since' must not be later than 'until'")
    events = get_db().list_events(
        limit=limit,
        token_id=token_id,
        token_type=token_type,
        source_ip=source_ip,
        severity=severity,
        source=source,
        since=_utc_iso(since),
        until=_utc_iso(until),
    )
    columns = (
        "id", "timestamp", "token_type", "source", "source_ip", "user_agent", "path",
        "action", "severity", "token_id", "token_label", "event_id", "account_id",
        "principal_arn", "details",
    )
    output = StringIO()
    writer = DictWriter(output, fieldnames=columns)
    writer.writeheader()
    for event in events:
        row = {**event, "details": str(event.get("details", {}))}
        writer.writerow({key: _safe_csv_value(value) for key, value in row.items()})
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="canarymesh-events.csv"'},
    )


@router.get("/notifications", summary="Inspect webhook delivery attempts")
def list_notifications(
    limit: int = Query(100, ge=1, le=500),
    _authorized: AdminPrincipal = Depends(require_read_access),
) -> list[dict[str, Any]]:
    return get_db().list_notifications(limit=limit)


@router.get("/audit", summary="List administrative action audit records")
def list_admin_audit(
    limit: int = Query(100, ge=1, le=500),
    _authorized: AdminPrincipal = Depends(require_read_access),
) -> list[dict[str, Any]]:
    return get_db().list_admin_actions(limit=limit)


@router.post("/notifications/{notification_id}/retry", status_code=status.HTTP_202_ACCEPTED)
def retry_notification(
    notification_id: int,
    request: Request,
    actor: AdminPrincipal = Depends(require_admin_access),
):
    db = get_db()
    if not db.retry_notification(notification_id):
        notification = db.get_notification(notification_id)
        if notification is None:
            raise HTTPException(status_code=404, detail="Notification delivery not found")
        raise HTTPException(
            status_code=409,
            detail="Only failed notification deliveries can be retried",
        )
    db.record_admin_action(
        actor.role,
        actor.key_id,
        "notification.retry",
        str(notification_id),
        request.client.host if request.client else "unknown",
    )
    return {"status": "queued", "notification_id": notification_id}
