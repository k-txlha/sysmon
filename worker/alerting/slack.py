"""
worker/alerting/slack.py

Sends a FiredAlert to a Slack Incoming Webhook using the Block Kit layout.
Block Kit gives rich formatting: severity color bar, structured fields,
and a direct link to the Sysmon dashboard (if configured).

Required env var:
    SLACK_WEBHOOK_URL — e.g. https://hooks.slack.com/services/T.../B.../xxx

Optional env var:
    SYSMON_DASHBOARD_URL — e.g. https://sysmon.yourcompany.com
                           (used to render an "Investigate →" button)
"""

from __future__ import annotations

import json
import requests
from typing import Optional

from detection.models import FiredAlert, Severity
from utils.logger import setup_logger

logger = setup_logger("alerting.slack")

# Map severity → Slack sidebar colour (hex strings accepted by Slack)
_SEVERITY_COLOR: dict[Severity, str] = {
    Severity.LOW:      "#2196F3",   # blue
    Severity.MEDIUM:   "#FF9800",   # amber
    Severity.HIGH:     "#F44336",   # red
    Severity.CRITICAL: "#7B1FA2",   # deep purple
}

# Map severity → emoji prefix for the title
_SEVERITY_EMOJI: dict[Severity, str] = {
    Severity.LOW:      "🔵",
    Severity.MEDIUM:   "🟠",
    Severity.HIGH:     "🔴",
    Severity.CRITICAL: "🟣",
}


def send_slack_alert(
    alert: FiredAlert,
    webhook_url: str,
    dashboard_url: Optional[str] = None,
) -> bool:
    """
    POST a rich Slack Block Kit message for the given FiredAlert.

    Returns True on success, False on any network or HTTP error.
    """
    emoji = _SEVERITY_EMOJI.get(alert.severity, "⚠️")
    color = _SEVERITY_COLOR.get(alert.severity, "#607D8B")

    # ── Compact context string ──────────────────────────────────────────
    ctx_lines = "\n".join(
        f"  • *{k}*: `{v}`"
        for k, v in alert.context.items()
        if v is not None
    )

    # ── Build Block Kit payload ─────────────────────────────────────────
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} Sysmon Alert — {alert.rule_name.replace('_', ' ').title()}",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Severity:*\n`{alert.severity.value}`",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Agent:*\n`{alert.agent_id}`",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Rule:*\n`{alert.rule_name}`",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Time (UTC):*\n`{alert.triggered_at.strftime('%Y-%m-%d %H:%M:%S')}`",
                },
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Summary:*\n{alert.message}",
            },
        },
    ]

    if ctx_lines:
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Context:*\n{ctx_lines}",
                },
            }
        )

    if dashboard_url:
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Investigate →"},
                        "url": f"{dashboard_url}/threats",
                        "style": "danger" if alert.severity in (Severity.HIGH, Severity.CRITICAL) else "primary",
                    }
                ],
            }
        )

    # Slack requires attachments for the sidebar colour bar
    payload = {
        "attachments": [
            {
                "color": color,
                "blocks": blocks,
                "fallback": f"[{alert.severity.value}] {alert.rule_name}: {alert.message}",
            }
        ]
    }

    try:
        response = requests.post(
            webhook_url,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            timeout=5,
        )
        if response.status_code == 200:
            logger.info(f"Slack alert sent for rule '{alert.rule_name}'.")
            return True
        else:
            logger.error(
                f"Slack webhook returned {response.status_code}: {response.text}"
            )
            return False

    except requests.RequestException as exc:
        logger.error(f"Failed to POST Slack alert: {exc}")
        return False
