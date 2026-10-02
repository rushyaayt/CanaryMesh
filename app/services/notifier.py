"""Slack and Discord notifications for standalone breach events."""

import logging
from typing import Any

import httpx

logger = logging.getLogger("canarymesh.notifier")


async def send_discord_alert(webhook_url: str, breach_info: dict[str, Any]) -> bool:
    embed = {
        "title": "CanaryMesh intrusion detected",
        "color": 15158332,
        "fields": [
            {"name": "Token Type", "value": str(breach_info["token_type"]), "inline": True},
            {"name": "Attacker IP", "value": str(breach_info["source_ip"]), "inline": True},
            {"name": "User Agent", "value": str(breach_info.get("user_agent") or "N/A")},
        ],
    }
    return await _post_notification(webhook_url, {"embeds": [embed]})


async def send_slack_alert(webhook_url: str, breach_info: dict[str, Any]) -> bool:
    message = (
        "*CanaryMesh intrusion detected*\n"
        f"*Token Type:* `{breach_info['token_type']}`\n"
        f"*Attacker IP:* `{breach_info['source_ip']}`\n"
        f"*User Agent:* `{breach_info.get('user_agent') or 'N/A'}`"
    )
    return await _post_notification(webhook_url, {"text": message})


async def send_webhook_alert(webhook_url: str, breach_info: dict[str, Any]) -> bool:
    if "discord.com/api/webhooks" in webhook_url:
        return await send_discord_alert(webhook_url, breach_info)
    if "hooks.slack.com" in webhook_url:
        return await send_slack_alert(webhook_url, breach_info)
    return await _post_notification(
        webhook_url,
        {"event": "canarymesh.breach.detected", "breach": breach_info},
    )


async def _post_notification(webhook_url: str, payload: dict[str, Any]) -> bool:
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            response = await client.post(webhook_url, json=payload)
        if response.is_success:
            return True
        logger.warning("Breach notification webhook returned HTTP %d", response.status_code)
    except httpx.HTTPError:
        logger.exception("Failed to deliver breach notification")
    return False
