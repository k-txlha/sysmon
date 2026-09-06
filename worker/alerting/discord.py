"""
worker/alerting/discord.py

Sends a FiredAlert to a Discord Incoming Webhook using Discord's Embed API.
Discord embeds support colour-coded sidebars, titled fields, and footers
— giving a visually clear alert card in any security-focused Discord channel.

Required env var:
    DISCORD_WEBHOOK_URL — e.g. https://discord.com/api/webhooks/xxx/yyy
"""

from __future__ import annotations

import json
import requests
from typing import Optional

from detection.models import FiredAlert, Severity
from utils.logger import setup_logger

logger = setup_logger("alerting.discord")

# Discord embed colours (decimal integers, not hex strings)
_SEVERITY_COLOR_INT: dict[Severity, int] = {
    Severity.LOW:      0x2196F3,   # blue
    Severity.MEDIUM:   0xFF9800,   # amber
    Severity.HIGH:     0xF44336,   # red
    Severity.CRITICAL: 0x7B1FA2,   # deep purple
}

_SEVERITY_EMOJI: dict[Severity, str] = {
    Severity.LOW:      "🔵",
    Severity.MEDIUM:   "🟠",
    Severity.HIGH:     "🔴",
    Severity.CRITICAL: "🟣",
}


def send_discord_alert(
    alert: FiredAlert,
    webhook_url: str,
    dashboard_url: Optional[str] = None,
) -> bool:
    """
    POST a rich Discord embed for the given FiredAlert.

    Returns True on success, False on any network or HTTP error.
    """
    emoji   = _SEVERITY_EMOJI.get(alert.severity, "⚠️")
    color   = _SEVERITY_COLOR_INT.get(alert.severity, 0x607D8B)

    # Build embed fields (max 25 per Discord's limit)
    fields = [
        {"name": "🔍 Rule",    "value": f"`{alert.rule_name}`",        "inline": True},
        {"name": "⚡ Severity", "value": f"`{alert.severity.value}`",  "inline": True},
        {"name": "🖥️ Agent",   "value": f"`{alert.agent_id}`",         "inline": True},
        {"name": "🕐 Time (UTC)", "value": f"`{alert.triggered_at.strftime('%Y-%m-%d %H:%M:%S')}`", "inline": True},
        {"name": "📋 Summary", "value": alert.message, "inline": False},
    ]

    # Append top context key-value pairs as fields (up to 5)
    ctx_items = list(alert.context.items())[:5]
    for key, val in ctx_items:
        if val is not None:
            fields.append({
                "name":   f"📌 {key.replace('_', ' ').title()}",
                "value":  f"`{val}`",
                "inline": True,
            })

    footer_text = "Sysmon Security Platform"
    if dashboard_url:
        footer_text += f" — {dashboard_url}"

    embed = {
        "title":       f"{emoji} Sysmon Alert: {alert.rule_name.replace('_', ' ').title()}",
        "description": f"**{alert.severity.value} severity** threat detected on `{alert.agent_id}`",
        "color":       color,
        "fields":      fields,
        "footer":      {"text": footer_text},
        "timestamp":   alert.triggered_at.isoformat(),
    }

    payload = {
        "username":   "Sysmon Security",
        "avatar_url": "https://raw.githubusercontent.com/k-txlha/sysmon/main/docs/logo.png",
        "embeds":     [embed],
    }

    try:
        response = requests.post(
            webhook_url,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            timeout=5,
        )
        # Discord returns 204 No Content on success
        if response.status_code in (200, 204):
            logger.info(f"Discord alert sent for rule '{alert.rule_name}'.")
            return True
        else:
            logger.error(
                f"Discord webhook returned {response.status_code}: {response.text}"
            )
            return False

    except requests.RequestException as exc:
        logger.error(f"Failed to POST Discord alert: {exc}")
        return False
