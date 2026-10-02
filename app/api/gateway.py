"""CanaryMesh Decoy Trap Gateway - Intercepts adversary credential misuse"""

import asyncio
import json
import uuid
from typing import Optional
from fastapi import APIRouter, BackgroundTasks, Request, Response
from app.config import get_settings
from app.core.decoys import get_decoy_response
from app.core.forensics import (
    analyze_user_agent,
    calculate_threat_severity,
    extract_client_ip,
    redact_sensitive_data,
    resolve_ip_geo,
    sanitize_request_headers,
    sanitize_request_payload,
)
from app.core.generators import compute_token_hash
from app.database import get_db
from app.services.alert_engine import broadcast_alert

router = APIRouter(tags=["Decoy Trap Gateway"])


async def _handle_trap_hit(
    request: Request,
    token_identifier: Optional[str],
    token_type_hint: str,
    background_tasks: BackgroundTasks,
) -> Response:
    """Core interception handler for any triggered honeytoken."""
    settings = get_settings()
    db = get_db()

    # Optional simulated realistic server latency
    if settings.decoy_delay_ms > 0:
        await asyncio.sleep(settings.decoy_delay_ms / 1000.0)

    # 1. Resolve token from database
    token = None
    if token_identifier:
        # Try direct ID lookup (e.g. /trap/canary_abcdef)
        token = db.get_token(token_identifier)
        if not token:
            # Try hash lookup
            token_hash = compute_token_hash(token_identifier)
            token = db.find_token_by_hash(token_hash)
        if not token and "_" in token_identifier:
            # Try parsing prefix if structured (e.g. canary_ci_canary_123456_...)
            for part in token_identifier.split("_"):
                if part.startswith("canary"):
                    candidate = db.get_token(part)
                    if candidate:
                        token = candidate
                        break

    # If still not found, check Authorization header
    if not token:
        auth_header = request.headers.get("authorization", "")
        if auth_header:
            raw_val = auth_header.replace("Bearer ", "").replace("Basic ", "").strip()
            token = db.find_token_by_hash(compute_token_hash(raw_val))
            if not token and "canary_" in raw_val:
                for part in raw_val.split("_"):
                    if part.startswith("canary"):
                        candidate = db.get_token(part)
                        if candidate:
                            token = candidate
                            break

    # Fallback to ephemeral dummy token record if unknown probe hits a trap endpoint
    if not token:
        token = {
            "id": token_identifier or f"unknown_{uuid.uuid4().hex[:8]}",
            "label": f"Unknown Probed Token ({token_identifier or 'decoy-route'})",
            "token_type": token_type_hint,
            "is_active": True,
            "webhook_url": None,
        }

    # 2. Extract forensic telemetry
    client_ip = extract_client_ip(request)
    ua_string = request.headers.get("user-agent", "Unknown Client")
    ua_info = analyze_user_agent(ua_string)
    geo_info = await resolve_ip_geo(client_ip)

    # Capture raw body if feasible
    raw_payload: Optional[str] = None
    try:
        body_bytes = await request.body()
        if body_bytes:
            raw_payload = body_bytes.decode("utf-8", errors="replace")[:2048]
    except Exception:
        raw_payload = None

    headers_dict = sanitize_request_headers(dict(request.headers))
    query_dict = redact_sensitive_data(dict(request.query_params))
    raw_payload = sanitize_request_payload(raw_payload)

    # Calculate threat severity
    severity = calculate_threat_severity(
        token.get("token_type", token_type_hint),
        not token.get("is_active", True),
        ua_info["is_automated_tool"],
    )

    alert_id = f"alert_{uuid.uuid4().hex[:12]}"
    status_code, decoy_body, decoy_headers = get_decoy_response(
        token.get("token_type", token_type_hint), request.url.path
    )

    # 3. Record alert forensic entry in SQLite
    if "id" in token and not token["id"].startswith("unknown_"):
        alert_record = db.record_alert(
            alert_id=alert_id,
            token_id=token["id"],
            token_label=token.get("label", "Canary Token"),
            token_type=token.get("token_type", token_type_hint),
            client_ip=client_ip,
            user_agent=ua_string,
            http_method=request.method,
            request_path=request.url.path,
            headers=headers_dict,
            payload=raw_payload,
            query_params=query_dict,
            geo_location=geo_info,
            decoy_response_code=status_code,
            decoy_response_body=decoy_body,
            severity=severity,
            notified=False,
        )
        alert_record["tool_detected"] = ua_info["tool_detected"]
        await broadcast_alert(alert_record)

        # 4. Persist webhook delivery and let the retry worker dispatch it.
        if token.get("webhook_url") or settings.default_webhook_url:
            db.create_notification(alert_record["id"])

    # 5. Return realistic decoy response
    return Response(
        content=decoy_body,
        status_code=status_code,
        headers=decoy_headers,
    )


# --- Dedicated Decoy Endpoints ---

@router.api_route(
    "/trap/{token_id}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"],
    summary="Universal Decoy Trap Catch-Point",
)
async def universal_trap_endpoint(
    token_id: str,
    request: Request,
    background_tasks: BackgroundTasks,
):
    return await _handle_trap_hit(request, token_id, "ci_ephemeral", background_tasks)


@router.api_route(
    "/v1/chat/completions",
    methods=["POST"],
    summary="Decoy OpenAI API Endpoint",
)
async def decoy_openai_completions(
    request: Request,
    background_tasks: BackgroundTasks,
):
    # Extract Bearer token
    auth = request.headers.get("authorization", "")
    token_val = auth.replace("Bearer ", "").strip() if auth else None
    return await _handle_trap_hit(request, token_val, "openai_key", background_tasks)


@router.api_route(
    "/v1/charges",
    methods=["GET", "POST"],
    summary="Decoy Stripe API Endpoint",
)
async def decoy_stripe_charges(
    request: Request,
    background_tasks: BackgroundTasks,
):
    auth = request.headers.get("authorization", "")
    token_val = auth.replace("Bearer ", "").strip() if auth else None
    return await _handle_trap_hit(request, token_val, "stripe_secret", background_tasks)


@router.api_route(
    "/v1/balance",
    methods=["GET"],
    summary="Decoy Stripe Balance Endpoint",
)
async def decoy_stripe_balance(
    request: Request,
    background_tasks: BackgroundTasks,
):
    auth = request.headers.get("authorization", "")
    token_val = auth.replace("Bearer ", "").strip() if auth else None
    return await _handle_trap_hit(request, token_val, "stripe_secret", background_tasks)


@router.api_route(
    "/api/aws/sts",
    methods=["GET", "POST"],
    summary="Decoy AWS STS Gateway",
)
async def decoy_aws_sts(
    request: Request,
    background_tasks: BackgroundTasks,
):
    token_val = request.query_params.get("AWSAccessKeyId") or request.headers.get("x-amz-security-token")
    return await _handle_trap_hit(request, token_val, "aws_iam", background_tasks)
