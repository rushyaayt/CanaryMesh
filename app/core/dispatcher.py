"""CanaryMesh Alert Dispatcher for Slack, Discord, SIEM, and Custom Webhooks"""

import asyncio
import logging
from typing import Any, Dict, Optional
import httpx
from app.config import get_settings

logger = logging.getLogger("canarymesh.dispatcher")


def build_slack_blocks(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Builds a high-impact Slack Block Kit message."""
    geo = alert.get("geo_location", {})
    location_str = f"{geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')} ({geo.get('isp', 'Unknown ISP')})"
    tool = alert.get("tool_detected", alert.get("user_agent", "Unknown"))

    return {
        "text": f"[CRITICAL BREACH ALERT] Honeytoken Tripped: {alert['token_label']}",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "DECEPTION DETECTED: HONEYTOKEN TRIPPED",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*Token:* `{alert['token_label']}` ({alert['token_type']})\n"
                        f"*Severity:* *{alert.get('severity', 'CRITICAL')}*\n"
                        f"*Adversary IP:* `{alert['client_ip']}`\n"
                        f"*Location:* {location_str}\n"
                        f"*Tool / Client:* `{tool}`\n"
                        f"*Request:* `{alert['http_method']} {alert['request_path']}`\n"
                        f"*Timestamp (UTC):* `{alert['timestamp']}`"
                    ),
                },
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": "*CanaryMesh Deception Mesh* | Zero False Positive Signal",
                    }
                ],
            },
        ],
    }


def build_discord_embed(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Builds a rich Discord Embed card with cyber red styling."""
    geo = alert.get("geo_location", {})
    location_str = f"{geo.get('city', 'Unknown')}, {geo.get('country', 'Unknown')}"

    return {
        "content": "**[BREACH DETECTED] Honeytoken Activated**",
        "embeds": [
            {
                "title": f"Honeytoken Tripped: {alert['token_label']}",
                "color": 16711765,  # Bright Cyber Red (#FF0055)
                "fields": [
                    {"name": "Token Type", "value": alert["token_type"], "inline": True},
                    {"name": "Severity", "value": alert.get("severity", "CRITICAL"), "inline": True},
                    {"name": "Client IP", "value": alert["client_ip"], "inline": True},
                    {"name": "Location", "value": location_str, "inline": True},
                    {"name": "Recon Tool", "value": alert.get("tool_detected", "Unknown"), "inline": True},
                    {"name": "HTTP Route", "value": f"{alert['http_method']} {alert['request_path']}", "inline": True},
                ],
                "footer": {"text": "CanaryMesh - Honeytoken-as-a-Service"},
                "timestamp": alert["timestamp"],
            }
        ],
    }


async def dispatch_alert(alert_data: Dict[str, Any], custom_webhook_url: Optional[str] = None) -> bool:
    """
    Asynchronously sends the alert payload to configured webhooks.
    Gracefully detects Slack, Discord, or generic SIEM webhooks.
    """
    settings = get_settings()
    target_url = custom_webhook_url or settings.default_webhook_url

    # Console Logging
    print(
        f"\n{'='*70}\n"
        f"[!] [CANARYMESH ALERT] HONEYTOKEN TRIPPED!\n"
        f"Token: {alert_data['token_label']} ({alert_data['token_type']})\n"
        f"Attacker IP: {alert_data['client_ip']} | Tool: {alert_data.get('tool_detected', 'N/A')}\n"
        f"Route: {alert_data['http_method']} {alert_data['request_path']}\n"
        f"{'='*70}\n"
    )

    if not target_url:
        logger.info("No webhook URL configured; alert recorded to SQLite database and console only.")
        return False

    try:
        payload: Dict[str, Any]
        if "hooks.slack.com" in target_url:
            payload = build_slack_blocks(alert_data)
        elif "discord.com/api/webhooks" in target_url:
            payload = build_discord_embed(alert_data)
        else:
            # Generic SIEM / JSON Webhook
            payload = {
                "event": "canarymesh.honeytoken.triggered",
                "alert": alert_data,
                "schema_version": "1.0",
            }

        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.post(target_url, json=payload)
            if resp.status_code in [200, 204]:
                logger.info("Successfully delivered alert to webhook: %s", target_url)
                return True
            else:
                logger.warning("Webhook returned non-200 code %d: %s", resp.status_code, resp.text)
                return False

    except Exception as exc:
        logger.error("Failed to deliver alert to webhook %s: %s", target_url, exc)
        return False
