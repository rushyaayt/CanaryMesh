"""Tests for standalone decoy traps, persistence, and cloud webhooks."""

from starlette.testclient import TestClient

from app.config import get_settings
from app.database import Database, get_db
from app.main import app


def test_config_trap_persists_breach_and_streams_live_alert():
    with TestClient(app) as client:
        with client.websocket_connect("/api/v1/ws/alerts") as websocket:
            response = client.get("/.env", headers={"user-agent": "scanner-test/1.0"})
            live_alert = websocket.receive_json()
        history = client.get("/api/v1/breaches")

    assert response.status_code == 200
    assert response.json()["DB_HOST"] == "10.0.0.50"
    assert response.json()["DB_PASS"] == "Canary_Trap_9823!"
    assert live_alert["token_type"] == "Environment File Scrape"
    assert live_alert["user_agent"] == "scanner-test/1.0"
    stored_alert = get_db().get_breach(live_alert["id"])
    assert stored_alert is not None
    assert stored_alert["path"].endswith("/.env")
    assert any(item["id"] == live_alert["id"] for item in history.json())


def test_breach_logs_survive_database_reopen(tmp_path):
    db_path = tmp_path / "breaches.db"
    first_db = Database(str(db_path))
    first_db.record_breach(
        breach_id="breach_persistence_test",
        token_type="AWS IAM Honeytoken",
        source_ip="203.0.113.8",
        user_agent="aws-cli/2",
        action="GetCallerIdentity",
    )

    reopened_db = Database(str(db_path))
    breaches = reopened_db.list_breaches()
    assert breaches[0]["id"] == "breach_persistence_test"
    assert breaches[0]["action"] == "GetCallerIdentity"


def test_aws_webhook_requires_configured_secret(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "aws_webhook_secret", "test-webhook-secret")
    monkeypatch.setattr(settings, "default_webhook_url", None)
    payload = {
        "detail": {
            "sourceIPAddress": "203.0.113.8",
            "eventName": "GetCallerIdentity",
            "userAgent": "aws-cli/2",
        }
    }

    with TestClient(app) as client:
        unauthorized = client.post("/api/v1/webhooks/aws", json=payload)
        wrong_secret = client.post(
            "/api/v1/webhooks/aws",
            json=payload,
            headers={"x-canary-webhook-secret": "incorrect"},
        )
        accepted = client.post(
            "/api/v1/webhooks/aws",
            json=payload,
            headers={"x-canary-webhook-secret": "test-webhook-secret"},
        )

    assert unauthorized.status_code == 401
    assert wrong_secret.status_code == 401
    assert accepted.status_code == 200
    breach = get_db().list_breaches()[0]
    assert breach["token_type"] == "AWS IAM Honeytoken"
    assert breach["source_ip"] == "203.0.113.8"
    assert breach["action"] == "GetCallerIdentity"


def test_aws_webhook_is_disabled_without_secret(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "aws_webhook_secret", None)

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/webhooks/aws",
            json={"detail": {"eventName": "GetCallerIdentity"}},
        )

    assert response.status_code == 503
