"""CanaryMesh Alerts & Forensic Inspection Endpoints"""

import uuid
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from app.core.dispatcher import dispatch_alert
from app.core.forensics import analyze_user_agent, calculate_threat_severity, resolve_ip_geo
from app.core.generators import compute_token_hash
from app.database import get_db
from app.models import AlertRecord, SimulationRequest

router = APIRouter(prefix="/api/v1", tags=["Alerts & Forensics"])


@router.get(
    "/alerts",
    response_model=List[AlertRecord],
    summary="List forensic breach alerts",
)
def list_alerts(
    token_id: Optional[str] = Query(None, description="Filter alerts by specific honeytoken ID"),
    limit: int = Query(50, ge=1, le=200),
):
    db = get_db()
    alerts = db.list_alerts(token_id=token_id, limit=limit)
    return [AlertRecord(**a) for a in alerts]


@router.get(
    "/alerts/{alert_id}",
    response_model=AlertRecord,
    summary="Get complete forensic breadcrumb details for an alert",
)
def get_alert(alert_id: str):
    db = get_db()
    alert = db.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert record not found")
    return AlertRecord(**alert)


@router.post(
    "/alerts/simulate",
    summary="Simulate an adversary accessing a honeytoken (for testing & verification)",
)
async def simulate_attack(sim: SimulationRequest):
    """
    Triggers a live breach simulation against an active honeytoken.
    Verifies the alert pipeline, forensic collector, and webhook notifications.
    """
    db = get_db()
    target_token = None

    if sim.token_id:
        target_token = db.get_token(sim.token_id)
    elif sim.token_value:
        target_token = db.find_token_by_hash(compute_token_hash(sim.token_value))
    else:
        # Pick the most recent active token
        active_tokens = db.list_tokens(is_active=True, limit=1)
        if active_tokens:
            target_token = active_tokens[0]

    if not target_token:
        raise HTTPException(
            status_code=400,
            detail="No active honeytoken found to simulate. Generate a honeytoken first.",
        )

    alert_id = f"alert_{uuid.uuid4().hex[:12]}"
    ua_info = analyze_user_agent(sim.simulated_tool or "curl/8.4.0")
    geo_info = await resolve_ip_geo(sim.simulated_ip or "198.51.100.42")
    severity = calculate_threat_severity(target_token["token_type"], False, ua_info["is_automated_tool"])

    simulated_headers = {
        "User-Agent": sim.simulated_tool or "curl/8.4.0",
        "Authorization": f"Bearer {target_token['display_token']}",
        "X-Simulated-Probe": "true",
        "Accept": "*/*",
    }

    alert_record = db.record_alert(
        alert_id=alert_id,
        token_id=target_token["id"],
        token_label=target_token["label"],
        token_type=target_token["token_type"],
        client_ip=sim.simulated_ip or "198.51.100.42",
        user_agent=sim.simulated_tool or "curl/8.4.0",
        http_method="POST",
        request_path=f"/trap/{target_token['id']}",
        headers=simulated_headers,
        payload=sim.payload,
        query_params={"action": "simulate_test"},
        geo_location=geo_info,
        decoy_response_code=403,
        decoy_response_body='{"error": "AccessDenied", "message": "CanaryMesh simulated intrusion"}',
        severity=severity,
        notified=True,
    )

    alert_record["tool_detected"] = ua_info["tool_detected"]

    # Dispatch to configured webhook
    delivered = await dispatch_alert(alert_record, target_token.get("webhook_url"))

    return {
        "status": "success",
        "message": f"Simulated attack recorded for honeytoken '{target_token['label']}'!",
        "alert_id": alert_id,
        "token_id": target_token["id"],
        "token_label": target_token["label"],
        "client_ip": sim.simulated_ip,
        "tool_detected": ua_info["tool_detected"],
        "webhook_delivered": delivered,
        "severity": severity,
    }
