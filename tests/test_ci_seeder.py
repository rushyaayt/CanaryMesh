"""Tests for CI/CD Ephemeral Seeding Engine"""

from starlette.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_seed_ci_endpoint():
    resp = client.post(
        "/api/v1/seed/ci",
        json={
            "repository": "corp/billing-service",
            "workflow": "ci-release-pipeline",
            "run_id": "run-40819",
            "commit_sha": "e3b0c44298fc1c149afbf4c8996fb924",
            "ttl_minutes": 30,
            "token_type": "ci_ephemeral",
        },
    )
    assert resp.status_code == 201
    data = resp.json()

    assert data["token_id"].startswith("canary_")
    assert data["env_variable_name"] == "CANARY_CI_RELEASE_KEY"
    assert data["token_value"].startswith("canary_ci_")
    assert "/trap/" in data["trap_endpoint"]
    assert "CANARY_CI_RELEASE_KEY=" in data["ci_export_snippet"]
    assert "CANARY_TRAP_ENDPOINT=" in data["ci_export_snippet"]


def test_seed_ci_aws_format():
    resp = client.post(
        "/api/v1/seed/ci",
        json={
            "repository": "corp/cloud-infra",
            "workflow": "terraform-plan",
            "ttl_minutes": 15,
            "token_type": "aws_iam",
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["env_variable_name"] == "AWS_ACCESS_KEY_ID"
    assert data["token_value"].startswith("AKIA")
    assert data["secret_component"] is not None


def test_quick_script_download():
    resp = client.get("/api/v1/seed/quick-script.sh")
    assert resp.status_code == 200
    assert "#!/usr/bin/env bash" in resp.text
    assert "CanaryMesh CI Seeder" in resp.text
    assert "curl" in resp.text
