"""CanaryMesh Token Management Endpoints"""

from datetime import datetime, timedelta, timezone
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from app.config import get_settings
from app.core.generators import compute_token_hash, generate_honeytoken
from app.database import get_db
from app.models import StatsResponse, TokenCreateRequest, TokenGeneratedResponse, TokenItem

router = APIRouter(prefix="/api/v1", tags=["Honeytokens"])


@router.post(
    "/tokens",
    response_model=TokenGeneratedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate a new honeytoken",
)
def create_token(req: TokenCreateRequest):
    settings = get_settings()
    db = get_db()

    token_id, raw_token, secret_component, display_token, instructions = generate_honeytoken(
        req.token_type, req.label
    )

    token_hash = compute_token_hash(raw_token)

    expires_at = None
    if req.ttl_minutes:
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=req.ttl_minutes)

    # Determine default trap URL
    if req.token_type.value == "openai_key":
        trap_url = f"{settings.public_url}/v1/chat/completions"
    elif req.token_type.value == "stripe_secret":
        trap_url = f"{settings.public_url}/v1/charges"
    elif req.token_type.value == "aws_iam":
        trap_url = f"{settings.public_url}/api/aws/sts"
    else:
        trap_url = f"{settings.public_url}/trap/{token_id}"

    db.save_token(
        token_id=token_id,
        token_value_hash=token_hash,
        display_token=display_token,
        token_type=req.token_type.value,
        label=req.label,
        environment=req.environment,
        expires_at=expires_at,
        webhook_url=req.webhook_url,
        metadata={
            **(req.metadata or {}),
            "trap_url": trap_url,
            "ttl_minutes": req.ttl_minutes,
        },
    )

    return TokenGeneratedResponse(
        id=token_id,
        token_type=req.token_type.value,
        label=req.label,
        environment=req.environment,
        raw_token=raw_token,
        display_token=display_token,
        secret_component=secret_component,
        trap_url=trap_url,
        created_at=datetime.now(timezone.utc).isoformat(),
        expires_at=expires_at.isoformat() if expires_at else None,
        instructions=instructions,
    )


@router.get(
    "/tokens",
    response_model=List[TokenItem],
    summary="List deployed honeytokens",
)
def list_tokens(
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    limit: int = Query(100, ge=1, le=500),
):
    db = get_db()
    tokens = db.list_tokens(is_active=is_active, limit=limit)
    return [TokenItem(**t) for t in tokens]


@router.get(
    "/tokens/{token_id}",
    response_model=TokenItem,
    summary="Get honeytoken details",
)
def get_token(token_id: str):
    db = get_db()
    token = db.get_token(token_id)
    if not token:
        raise HTTPException(status_code=404, detail="Honeytoken not found")
    return TokenItem(**token)


@router.delete(
    "/tokens/{token_id}",
    summary="Revoke a honeytoken",
)
def revoke_token(token_id: str):
    db = get_db()
    success = db.revoke_token(token_id)
    if not success:
        raise HTTPException(status_code=404, detail="Honeytoken not found or already deleted")
    return {"status": "success", "message": f"Honeytoken {token_id} revoked."}


@router.get(
    "/stats",
    response_model=StatsResponse,
    summary="Summary telemetry of deception mesh",
)
def get_stats():
    db = get_db()
    stats = db.get_stats()
    return StatsResponse(**stats)
