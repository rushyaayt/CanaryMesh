"""Tests for Decoy Trap Gateway & Interception Mechanics"""

import pytest
from starlette.testclient import TestClient
from app.database import get_db
from app.main import app


@pytest.fixture
def client():
    # Use a memory/test database instance
    db = get_db()
    with TestClient(app) as test_client:
        yield test_client


def test_health_check(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"


def test_universal_trap_intercept(client):
    # 1. Create an active honeytoken
    create_resp = client.post(
        "/api/v1/tokens",
        json={
            "token_type": "ci_ephemeral",
            "label": "gateway-test-ci",
            "environment": "test-env",
            "ttl_minutes": 60,
        },
    )
    assert create_resp.status_code == 201
    tok_data = create_resp.json()
    tok_id = tok_data["id"]
    raw_token = tok_data["raw_token"]

    # 2. Probe the trap URL with simulated adversary request
    trap_resp = client.post(
        f"/trap/{tok_id}",
        headers={
            "User-Agent": "curl/8.4.0",
            "Authorization": f"Bearer {raw_token}",
        },
        json={"exploit_attempt": "env_dump"},
    )
    # The decoy response should return 403 Forbidden with realistic error message
    assert trap_resp.status_code == 403
    body = trap_resp.json()
    assert body["status"] == "error"
    assert "FORBIDDEN" in body["error_code"]

    # 3. Verify alert recorded in database
    alerts_resp = client.get(f"/api/v1/alerts?token_id={tok_id}")
    assert alerts_resp.status_code == 200
    alerts = alerts_resp.json()
    assert len(alerts) >= 1
    alert = alerts[0]
    assert alert["token_id"] == tok_id
    assert alert["token_label"] == "gateway-test-ci"
    assert "curl" in alert["headers"]["user-agent"].lower()


def test_decoy_openai_completions(client):
    # 1. Create OpenAI honeytoken
    create_resp = client.post(
        "/api/v1/tokens",
        json={
            "token_type": "openai_key",
            "label": "test-openai-canary",
            "environment": "developer-laptop",
        },
    )
    assert create_resp.status_code == 201
    tok_data = create_resp.json()
    raw_token = tok_data["raw_token"]

    # 2. Call /v1/chat/completions using Bearer honeytoken
    chat_resp = client.post(
        "/v1/chat/completions",
        headers={"Authorization": f"Bearer {raw_token}"},
        json={"model": "gpt-4", "messages": [{"role": "user", "content": "hello"}]},
    )
    # Returns 429 quota error decoy
    assert chat_resp.status_code == 429
    assert "insufficient_quota" in chat_resp.text
    assert "openai-organization" in chat_resp.headers


def test_decoy_stripe_charges(client):
    # 1. Create Stripe honeytoken
    create_resp = client.post(
        "/api/v1/tokens",
        json={
            "token_type": "stripe_secret",
            "label": "test-stripe-canary",
            "environment": "staging-checkout",
        },
    )
    assert create_resp.status_code == 201
    raw_token = create_resp.json()["raw_token"]

    # 2. Probe /v1/charges
    stripe_resp = client.post(
        "/v1/charges",
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert stripe_resp.status_code == 401
    assert "api_key_expired" in stripe_resp.text
