"""Tests for Alert Dispatcher and Payload Formatting"""

import pytest
from app.core.dispatcher import build_discord_embed, build_slack_blocks, dispatch_alert


def test_build_slack_blocks():
    alert = {
        "id": "alert_12345",
        "token_id": "tok_999",
        "token_label": "ci-prod-key",
        "token_type": "ci_ephemeral",
        "severity": "CRITICAL",
        "client_ip": "198.51.100.99",
        "user_agent": "curl/8.4.0",
        "http_method": "POST",
        "request_path": "/trap/tok_999",
        "timestamp": "2026-09-13T12:00:00Z",
        "geo_location": {"city": "Zurich", "country": "Switzerland", "isp": "Datacenter Hosting"},
    }

    blocks = build_slack_blocks(alert)
    assert "blocks" in blocks
    assert len(blocks["blocks"]) >= 3
    header_text = blocks["blocks"][0]["text"]["text"]
    assert "DECEPTION DETECTED" in header_text

    section_text = blocks["blocks"][1]["text"]["text"]
    assert "ci-prod-key" in section_text
    assert "198.51.100.99" in section_text
    assert "Zurich" in section_text


def test_build_discord_embed():
    alert = {
        "id": "alert_54321",
        "token_label": "aws-backup-key",
        "token_type": "aws_iam",
        "severity": "CRITICAL",
        "client_ip": "203.0.113.5",
        "tool_detected": "AWS CLI",
        "http_method": "GET",
        "request_path": "/api/aws/sts",
        "timestamp": "2026-09-13T12:30:00Z",
        "geo_location": {"city": "Tokyo", "country": "Japan"},
    }

    embed = build_discord_embed(alert)
    assert "embeds" in embed
    card = embed["embeds"][0]
    assert card["title"] == "Honeytoken Tripped: aws-backup-key"
    assert card["color"] == 16711765  # Cyber red
    field_names = [f["name"] for f in card["fields"]]
    assert "Client IP" in field_names
    assert "Recon Tool" in field_names


def test_dispatch_alert_no_webhook():
    import asyncio
    alert = {
        "token_label": "dummy",
        "token_type": "ci_ephemeral",
        "client_ip": "127.0.0.1",
        "http_method": "GET",
        "request_path": "/trap",
    }
    # With no webhook URL configured, should safely log to console and return False
    delivered = asyncio.run(dispatch_alert(alert, custom_webhook_url=None))
    assert delivered is False
