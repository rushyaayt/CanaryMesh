"""Historical standalone breach event API."""

from typing import Any

from fastapi import APIRouter, Query

from app.database import get_db

router = APIRouter(prefix="/api/v1", tags=["Alerts & Forensics"])


@router.get("/breaches", summary="List persisted standalone breach events")
def list_breaches(limit: int = Query(50, ge=1, le=200)) -> list[dict[str, Any]]:
    return get_db().list_breaches(limit=limit)
