"""Tests for incident authentication, decoy traps, persistence, and webhooks."""

import asyncio
import json
import sqlite3
import uuid
from datetime import datetime, timezone

from starlette.testclient import TestClient

from app.config import get_settings
from app.database import Database, get_db
from app.main import app

ADMIN_KEY = "admin-test-key-0123456789abcdef0123456789"
AWS_WEBHOOK_SECRET = "aws-test-secret-0123456789abcdef0123456789"


def _aws_payload(event_id: str = "event-test-123") -> dict:
    return {
        "account": "123456789012",
        "detail": {
            "eventID": event_id,
            "eventTime": datetime.now(timezone.utc).isoformat(),
            "eventSource": "sts.amazonaws.com",
            "userIdentity": {"arn": "arn:aws:iam::123456789012:user/canary"},
            "sourceIPAddress": "203.0.113.8",
            "eventName": "GetCallerIdentity",
            "userAgent": "aws-cli/2",
        },
    }


def test_config_trap_persists_breach_and_streams_live_alert(monkeypatch):
    monkeypatch.setattr(get_settings(), "admin_api_key", ADMIN_KEY)
    with TestClient(app) as client:
        with client.websocket_connect(
            "/api/v1/ws/alerts",
            subprotocols=["canarymesh", f"canarymesh-auth.{ADMIN_KEY}"],
        ) as websocket:
            response = client.get("/.env", headers={"user-agent": "scanner-test/1.0"})
            live_alert = websocket.receive_json()
        history = client.get(
            "/api/v1/breaches",
            headers={"Authorization": f"Bearer {ADMIN_KEY}"},
        )

    assert response.status_code == 200
    assert response.json()["DB_HOST"] == "db.canarymesh.invalid"
    assert response.json()["DB_PASS"] == "NOT_A_REAL_CREDENTIAL"
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


def test_database_migration_redacts_legacy_request_secrets(tmp_path):
    db_path = tmp_path / "legacy-alerts.db"
    db = Database(str(db_path))
    db.save_token(
        token_id="migration-token",
        token_value_hash="hash",
        display_token="masked",
        token_type="ci_ephemeral",
        label="migration-test",
        environment="test",
    )
    db.record_alert(
        alert_id="migration-alert",
        token_id="migration-token",
        token_label="migration-test",
        token_type="ci_ephemeral",
        client_ip="192.0.2.1",
        user_agent="legacy-test",
        http_method="POST",
        request_path="/trap/migration-token",
        headers={},
        payload="{}",
        query_params={},
        geo_location={},
        decoy_response_code=403,
        decoy_response_body=None,
    )
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE alerts SET request_headers_json = ?, request_payload = ?, query_params_json = ? "
            "WHERE id = ?",
            (
                json.dumps({"Authorization": "legacy-secret"}),
                json.dumps({"api_key": "legacy-secret"}),
                json.dumps({"token": "legacy-secret"}),
                "migration-alert",
            ),
        )
        connection.execute("DELETE FROM schema_migrations WHERE version = 1")

    migrated_alert = Database(str(db_path)).get_alert("migration-alert")
    assert migrated_alert["headers"]["Authorization"] == "[REDACTED]"
    assert migrated_alert["payload"] == '{"api_key": "[REDACTED]"}'
    assert migrated_alert["query_params"]["token"] == "[REDACTED]"


def test_aws_webhook_requires_configured_secret(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "aws_webhook_secret", AWS_WEBHOOK_SECRET)
    monkeypatch.setattr(settings, "aws_account_id", "123456789012")
    monkeypatch.setattr(settings, "aws_honeytoken_principal_arn", "arn:aws:iam::123456789012:user/canary")
    monkeypatch.setattr(settings, "default_webhook_url", None)
    payload = _aws_payload()

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
            headers={"x-canary-webhook-secret": AWS_WEBHOOK_SECRET},
        )

    assert unauthorized.status_code == 401
    assert wrong_secret.status_code == 401
    assert accepted.status_code == 200
    breach = next(
        item for item in get_db().list_breaches() if item.get("event_id") == "event-test-123"
    )
    assert breach["token_type"] == "AWS IAM Honeytoken"
    assert breach["source_ip"] == "203.0.113.8"
    assert breach["action"] == "GetCallerIdentity"


def test_aws_webhook_rejects_wrong_account_or_principal(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "aws_webhook_secret", AWS_WEBHOOK_SECRET)
    monkeypatch.setattr(settings, "aws_account_id", "123456789012")
    monkeypatch.setattr(settings, "aws_honeytoken_principal_arn", "arn:aws:iam::123456789012:user/canary")
    payload = _aws_payload("event-wrong-account")
    payload["account"] = "999999999999"
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/webhooks/aws",
            json=payload,
            headers={"x-canary-webhook-secret": AWS_WEBHOOK_SECRET},
        )
        wrong_principal_payload = _aws_payload("event-wrong-principal")
        wrong_principal_payload["detail"]["userIdentity"]["arn"] = (
            "arn:aws:iam::123456789012:user/not-the-canary"
        )
        wrong_principal = client.post(
            "/api/v1/webhooks/aws",
            json=wrong_principal_payload,
            headers={"x-canary-webhook-secret": AWS_WEBHOOK_SECRET},
        )
    assert response.status_code == 403
    assert wrong_principal.status_code == 403


def test_aws_webhook_rejects_expired_event(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "aws_webhook_secret", AWS_WEBHOOK_SECRET)
    monkeypatch.setattr(settings, "aws_account_id", "123456789012")
    monkeypatch.setattr(settings, "aws_honeytoken_principal_arn", "arn:aws:iam::123456789012:user/canary")
    payload = _aws_payload("event-too-old")
    payload["detail"]["eventTime"] = "2020-01-01T00:00:00Z"

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/webhooks/aws",
            json=payload,
            headers={"x-canary-webhook-secret": AWS_WEBHOOK_SECRET},
        )
    assert response.status_code == 400


def test_aws_webhook_deduplicates_replayed_event(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "aws_webhook_secret", AWS_WEBHOOK_SECRET)
    monkeypatch.setattr(settings, "aws_account_id", "123456789012")
    monkeypatch.setattr(settings, "aws_honeytoken_principal_arn", "arn:aws:iam::123456789012:user/canary")
    payload = _aws_payload("event-idempotent-test")
    with TestClient(app) as client:
        first = client.post(
            "/api/v1/webhooks/aws",
            json=payload,
            headers={"x-canary-webhook-secret": AWS_WEBHOOK_SECRET},
        )
        second = client.post(
            "/api/v1/webhooks/aws",
            json=payload,
            headers={"x-canary-webhook-secret": AWS_WEBHOOK_SECRET},
        )
    assert first.status_code == second.status_code == 200
    assert sum(
        event.get("event_id") == "event-idempotent-test"
        for event in get_db().list_breaches(limit=100)
    ) == 1


def test_aws_webhook_is_disabled_without_secret(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "aws_webhook_secret", None)

    with TestClient(app) as client:
        response = client.post(
            "/api/v1/webhooks/aws",
            json=_aws_payload("disabled-test"),
        )

    assert response.status_code == 503


def test_event_history_requires_admin_auth_and_supports_filtering(monkeypatch):
    monkeypatch.setattr(get_settings(), "admin_api_key", ADMIN_KEY)
    with TestClient(app) as client:
        unauthenticated = client.get("/api/v1/events")
        filtered = client.get(
            "/api/v1/events?source=decoy&token_type=Environment%20File%20Scrape",
            headers={"Authorization": f"Bearer {ADMIN_KEY}"},
        )
        exported = client.get(
            "/api/v1/events/export?source=decoy&token_type=Environment%20File%20Scrape",
            headers={"Authorization": f"Bearer {ADMIN_KEY}"},
        )

    assert unauthenticated.status_code == 401
    assert filtered.status_code == 200
    assert all(event["source"] == "decoy" for event in filtered.json())
    assert exported.status_code == 200
    assert "text/csv" in exported.headers["content-type"]
    assert "canarymesh-events.csv" in exported.headers["content-disposition"]


def test_sensitive_history_fails_closed_without_admin_key(monkeypatch):
    monkeypatch.setattr(get_settings(), "admin_api_key", None)
    with TestClient(app) as client:
        response = client.get("/api/v1/breaches")
    assert response.status_code == 503


def test_notification_delivery_retries_and_survives_failure(monkeypatch, tmp_path):
    import app.services.alert_engine as alert_engine

    db = Database(str(tmp_path / "notifications.db"))
    monkeypatch.setattr(alert_engine, "get_db", lambda: db)
    monkeypatch.setattr(get_settings(), "default_webhook_url", "https://hooks.example.invalid")

    async def no_wait(_seconds):
        return None

    attempts = 0

    async def fail_delivery(_url, _event):
        nonlocal attempts
        attempts += 1
        return False

    monkeypatch.setattr(alert_engine.asyncio, "sleep", no_wait)
    monkeypatch.setattr(alert_engine, "send_webhook_alert", fail_delivery)
    breach = asyncio.run(
        alert_engine.register_breach(
            token_type="Environment File Scrape",
            source_ip="203.0.113.9",
        )
    )
    notification = db.list_notifications()[0]
    asyncio.run(alert_engine.process_notification(notification["id"]))

    failed = db.get_notification(notification["id"])
    assert attempts == 3
    assert failed["status"] == "failed"
    assert failed["attempts"] == 3

    async def succeed_delivery(_url, _event):
        return True

    monkeypatch.setattr(alert_engine, "send_webhook_alert", succeed_delivery)
    assert db.retry_notification(notification["id"])
    asyncio.run(alert_engine.process_notification(notification["id"]))
    assert db.get_notification(notification["id"])["status"] == "sent"
    assert db.get_event(breach["id"])["source_ip"] == "203.0.113.9"


def test_notification_worker_uses_token_specific_webhook(monkeypatch, tmp_path):
    import app.services.alert_engine as alert_engine

    db = Database(str(tmp_path / "token-notifications.db"))
    db.save_token(
        token_id="token-webhook-test",
        token_value_hash="hash",
        display_token="masked",
        token_type="ci_ephemeral",
        label="token-webhook-test",
        environment="test",
        webhook_url="https://hooks.example.invalid/custom",
    )
    alert = db.record_alert(
        alert_id="alert-custom-webhook",
        token_id="token-webhook-test",
        token_label="token-webhook-test",
        token_type="ci_ephemeral",
        client_ip="192.0.2.10",
        user_agent="test",
        http_method="POST",
        request_path="/trap/token-webhook-test",
        headers={},
        payload=None,
        query_params={},
        geo_location={},
        decoy_response_code=403,
        decoy_response_body=None,
    )
    notification = db.create_notification(alert["id"])
    monkeypatch.setattr(alert_engine, "get_db", lambda: db)
    monkeypatch.setattr(get_settings(), "default_webhook_url", None)
    received_urls = []

    async def deliver(url, _event):
        received_urls.append(url)
        return True

    monkeypatch.setattr(alert_engine, "send_webhook_alert", deliver)
    asyncio.run(alert_engine.process_notification(notification["id"]))

    assert received_urls == ["https://hooks.example.invalid/custom"]
    assert db.get_notification(notification["id"])["status"] == "sent"
    assert db.get_alert(alert["id"])["notified"] is True


def test_csv_export_escapes_formula_like_values(monkeypatch):
    monkeypatch.setattr(get_settings(), "admin_api_key", ADMIN_KEY)
    breach_id = f"breach_csv_formula_{uuid.uuid4().hex}"
    get_db().record_breach(
        breach_id=breach_id,
        token_type="Environment File Scrape",
        source_ip="=HYPERLINK(\"https://example.invalid\")",
        user_agent="csv-test",
    )
    with TestClient(app) as client:
        response = client.get(
            "/api/v1/events/export?source=decoy",
            headers={"Authorization": f"Bearer {ADMIN_KEY}"},
        )
    assert response.status_code == 200
    assert "'=HYPERLINK" in response.text
