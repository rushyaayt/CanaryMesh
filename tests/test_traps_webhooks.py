"""Tests for incident authentication, decoy traps, persistence, and webhooks."""

import asyncio
import hashlib
import hmac
import json
import sqlite3
import time
import uuid
from datetime import datetime, timezone
import socket

import pytest
from fastapi import HTTPException
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


def _signed_aws_request(payload: dict, timestamp: int | None = None) -> tuple[bytes, dict[str, str]]:
    body = json.dumps(payload).encode("utf-8")
    timestamp_text = str(timestamp or int(time.time()))
    signature = hmac.new(
        AWS_WEBHOOK_SECRET.encode("utf-8"),
        timestamp_text.encode("ascii") + b"." + body,
        hashlib.sha256,
    ).hexdigest()
    return body, {
        "content-type": "application/json",
        "x-canary-timestamp": timestamp_text,
        "x-canary-signature": f"sha256={signature}",
    }


def _post_signed_aws(client, payload: dict, timestamp: int | None = None):
    body, headers = _signed_aws_request(payload, timestamp)
    return client.post("/api/v1/webhooks/aws", content=body, headers=headers)


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
            content=json.dumps(payload),
            headers={
                "content-type": "application/json",
                "x-canary-timestamp": str(int(time.time())),
                "x-canary-signature": "incorrect",
            },
        )
        accepted = _post_signed_aws(client, payload)

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
        response = _post_signed_aws(client, payload)
        wrong_principal_payload = _aws_payload("event-wrong-principal")
        wrong_principal_payload["detail"]["userIdentity"]["arn"] = (
            "arn:aws:iam::123456789012:user/not-the-canary"
        )
        wrong_principal = _post_signed_aws(client, wrong_principal_payload)
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
        response = _post_signed_aws(client, payload)
    assert response.status_code == 400


def test_aws_webhook_deduplicates_replayed_event(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "aws_webhook_secret", AWS_WEBHOOK_SECRET)
    monkeypatch.setattr(settings, "aws_account_id", "123456789012")
    monkeypatch.setattr(settings, "aws_honeytoken_principal_arn", "arn:aws:iam::123456789012:user/canary")
    payload = _aws_payload("event-idempotent-test")
    with TestClient(app) as client:
        body, headers = _signed_aws_request(payload)
        first = client.post("/api/v1/webhooks/aws", content=body, headers=headers)
        second = client.post("/api/v1/webhooks/aws", content=body, headers=headers)
    assert first.status_code == 200
    assert second.status_code == 409
    assert sum(
        event.get("event_id") == "event-idempotent-test"
        for event in get_db().list_breaches(limit=100)
    ) == 1


def test_aws_webhook_is_disabled_without_secret(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "aws_webhook_secret", None)

    with TestClient(app) as client:
        response = client.post("/api/v1/webhooks/aws", json=_aws_payload("disabled-test"))

    assert response.status_code == 503


def test_aws_webhook_rejects_stale_signature_and_oversized_payload(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "aws_webhook_secret", AWS_WEBHOOK_SECRET)
    payload = _aws_payload("stale-signature")
    body, headers = _signed_aws_request(payload, int(time.time()) - 301)
    with TestClient(app) as client:
        stale = client.post("/api/v1/webhooks/aws", content=body, headers=headers)

        monkeypatch.setattr(settings, "webhook_max_body_bytes", 32)
        oversized = client.post(
            "/api/v1/webhooks/aws",
            content=b"x" * 33,
            headers={"content-type": "application/json"},
        )
    assert stale.status_code == 401
    assert oversized.status_code == 413


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


def test_readonly_key_cannot_mutate_management_endpoints(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "admin_api_key", ADMIN_KEY)
    monkeypatch.setattr(settings, "readonly_api_key", "viewer-key-0123456789abcdef0123456789")
    with TestClient(app) as client:
        read = client.get(
            "/api/v1/tokens",
            headers={"Authorization": "Bearer viewer-key-0123456789abcdef0123456789"},
        )
        create = client.post(
            "/api/v1/tokens",
            json={"token_type": "ci_ephemeral", "label": "viewer-denied"},
            headers={"Authorization": "Bearer viewer-key-0123456789abcdef0123456789"},
        )
        created = client.post(
            "/api/v1/tokens",
            json={"token_type": "ci_ephemeral", "label": "admin-created"},
            headers={"Authorization": f"Bearer {ADMIN_KEY}"},
        )
        audit = client.get(
            "/api/v1/audit",
            headers={"Authorization": "Bearer viewer-key-0123456789abcdef0123456789"},
        )
    assert read.status_code == 200
    assert create.status_code == 403
    assert created.status_code == 201
    assert any(entry["action"] == "token.create" for entry in audit.json())


def test_previous_admin_key_supports_staged_rotation(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "admin_api_key", ADMIN_KEY)
    monkeypatch.setattr(
        settings, "previous_admin_api_key", "previous-admin-0123456789abcdef0123456789"
    )
    with TestClient(app) as client:
        old_key_works_during_rotation = client.get(
            "/api/v1/stats",
            headers={"Authorization": "Bearer previous-admin-0123456789abcdef0123456789"},
        )
    assert old_key_works_during_rotation.status_code == 200


def test_outbound_webhook_url_rejects_http_and_loopback():
    from app.services.webhook_security import validate_webhook_url

    with pytest.raises(HTTPException) as insecure:
        asyncio.run(validate_webhook_url("http://example.com/hook"))
    with pytest.raises(HTTPException) as loopback:
        asyncio.run(validate_webhook_url("https://127.0.0.1/hook"))
    with pytest.raises(HTTPException) as malformed:
        asyncio.run(validate_webhook_url("https://example.com:invalid/hook"))
    assert insecure.value.status_code == 422
    assert loopback.value.status_code == 422
    assert malformed.value.status_code == 422


def test_webhook_resolver_rejects_mixed_public_and_private_dns(monkeypatch):
    import app.services.webhook_security as webhook_security

    class FakeLoop:
        async def getaddrinfo(self, *_args, **_kwargs):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
            ]

    monkeypatch.setattr(webhook_security.asyncio, "get_running_loop", lambda: FakeLoop())
    resolver = webhook_security.PublicAddressResolver()
    with pytest.raises(OSError):
        asyncio.run(resolver.resolve("mixed.example", 443, family=socket.AF_UNSPEC))
    monkeypatch.setattr(get_settings(), "webhook_allowed_hosts", ["mixed.example"])
    assert len(
        asyncio.run(resolver.resolve("mixed.example", 443, family=socket.AF_UNSPEC))
    ) == 2

    class MetadataLoop:
        async def getaddrinfo(self, *_args, **_kwargs):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443)),
            ]

    monkeypatch.setattr(webhook_security.asyncio, "get_running_loop", lambda: MetadataLoop())
    with pytest.raises(OSError):
        asyncio.run(resolver.resolve("mixed.example", 443, family=socket.AF_UNSPEC))


def test_webhook_rate_limit_uses_atomic_database_counter(tmp_path):
    db = Database(str(tmp_path / "rate-limit.db"))
    key = f"aws:test:{uuid.uuid4().hex}"
    assert db.check_webhook_rate_limit(key, limit=1, window_seconds=60)
    assert not db.check_webhook_rate_limit(key, limit=1, window_seconds=60)


def test_database_backup_is_integrity_checked(tmp_path):
    source_path = tmp_path / "source.db"
    backup_path = tmp_path / "backup.db"
    db = Database(str(source_path))
    db.record_breach(
        breach_id="backup-test-event",
        token_type="Environment File Scrape",
        source_ip="203.0.113.1",
        user_agent="backup-test",
    )
    assert db.integrity_check() == "ok"
    assert db.backup_to(str(backup_path)) == "ok"
    restored = Database(str(backup_path))
    assert restored.integrity_check() == "ok"
    assert restored.get_breach("backup-test-event") is not None


def test_event_retention_purges_old_breaches_and_deliveries(tmp_path):
    db_path = tmp_path / "retention.db"
    db = Database(str(db_path))
    event = db.record_breach(
        breach_id="retention-test-event",
        token_type="Environment File Scrape",
        source_ip="203.0.113.2",
        user_agent="retention-test",
        enqueue_notification=True,
    )
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE breach_logs SET timestamp = ? WHERE id = ?",
            ("2000-01-01T00:00:00+00:00", event["id"]),
        )
        connection.execute(
            "UPDATE notification_deliveries SET created_at = ? WHERE event_id = ?",
            ("2000-01-01T00:00:00+00:00", event["id"]),
        )
    assert db.purge_old_events(retention_days=1) == 1
    assert db.get_breach(event["id"]) is None
    assert db.list_notifications() == []


def test_expired_final_notification_lease_becomes_failed(tmp_path):
    db_path = tmp_path / "expired-lease.db"
    db = Database(str(db_path))
    notification = db.create_notification("missing-event")
    claim = db.claim_notification("worker-one", notification_id=notification["id"])
    assert claim is not None
    db.update_notification(
        notification["id"], "processing", 3, worker_id="worker-one"
    )
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE notification_deliveries SET lease_until = ? WHERE id = ?",
            ("2000-01-01T00:00:00+00:00", notification["id"]),
        )

    assert db.claim_notification("worker-two") is None
    terminal = db.get_notification(notification["id"])
    assert terminal["status"] == "failed"
    assert terminal["last_error"] == "Final delivery lease expired"


def test_notification_delivery_retries_and_survives_failure(monkeypatch, tmp_path):
    import app.services.alert_engine as alert_engine

    db_path = tmp_path / "notifications.db"
    db = Database(str(db_path))
    monkeypatch.setattr(alert_engine, "get_db", lambda: db)
    monkeypatch.setattr(get_settings(), "default_webhook_url", "https://hooks.example.invalid")

    attempts = 0

    async def fail_delivery(_url, _event):
        nonlocal attempts
        attempts += 1
        return False

    monkeypatch.setattr(alert_engine, "send_webhook_alert", fail_delivery)
    breach = asyncio.run(
        alert_engine.register_breach(
            token_type="Environment File Scrape",
            source_ip="203.0.113.9",
        )
    )
    notification = db.list_notifications()[0]
    for _ in range(3):
        with sqlite3.connect(db_path) as connection:
            connection.execute(
                "UPDATE notification_deliveries SET next_attempt_at = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), notification["id"]),
            )
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


def test_notification_outbox_is_transactional_and_claimed_once(monkeypatch, tmp_path):
    import app.services.alert_engine as alert_engine

    db = Database(str(tmp_path / "outbox.db"))
    monkeypatch.setattr(alert_engine, "get_db", lambda: db)
    monkeypatch.setattr(
        get_settings(), "default_webhook_url", "https://hooks.example.invalid"
    )
    breach = asyncio.run(
        alert_engine.register_breach(
            token_type="Environment File Scrape",
            source_ip="203.0.113.10",
        )
    )
    notification = db.list_notifications()[0]
    first_claim = db.claim_notification("worker-one")
    second_claim = db.claim_notification("worker-two")

    assert notification["event_id"] == breach["id"]
    assert first_claim is not None
    assert second_claim is None


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
