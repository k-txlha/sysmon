"""
worker/alerting/dispatcher.py

The AlertDispatcher is a thin fan-out layer.  Given a FiredAlert, it
checks which channels are configured (via environment variables loaded
at startup) and calls each enabled sender.

Channel configuration is driven entirely by environment variables so
startups can enable/disable channels by editing their .env — no code
changes needed.

Channels:
    Slack   — set SLACK_WEBHOOK_URL
    Discord — set DISCORD_WEBHOOK_URL
    Email   — set SMTP_HOST + SMTP_USERNAME + SMTP_PASSWORD + SMTP_TO
"""

from __future__ import annotations

from typing import List, Optional

from detection.models import FiredAlert
from utils.config import settings
from utils.logger import setup_logger

logger = setup_logger("alerting.dispatcher")


class AlertDispatcher:
    """
    Reads alert channel configuration from `settings` once at init time
    and dispatches FiredAlert objects to every configured channel.

    Import channel senders lazily to avoid hard import errors when
    optional dependencies (e.g. smtplib config) are not present.
    """

    def __init__(self) -> None:
        self._slack_url:      Optional[str]  = getattr(settings, "SLACK_WEBHOOK_URL", None) or None
        self._discord_url:    Optional[str]  = getattr(settings, "DISCORD_WEBHOOK_URL", None) or None
        self._dashboard_url:  Optional[str]  = getattr(settings, "SYSMON_DASHBOARD_URL", None) or None

        # Email settings
        self._smtp_host:     Optional[str]  = getattr(settings, "SMTP_HOST", None) or None
        self._smtp_port:     int            = int(getattr(settings, "SMTP_PORT", 587) or 587)
        self._smtp_user:     Optional[str]  = getattr(settings, "SMTP_USERNAME", None) or None
        self._smtp_pass:     Optional[str]  = getattr(settings, "SMTP_PASSWORD", None) or None
        self._smtp_from:     Optional[str]  = getattr(settings, "SMTP_FROM", None) or None
        self._smtp_to:       List[str]      = [
            addr.strip()
            for addr in (getattr(settings, "SMTP_TO", "") or "").split(",")
            if addr.strip()
        ]

        self._log_configured_channels()

    def _log_configured_channels(self) -> None:
        channels = []
        if self._slack_url:
            channels.append("Slack")
        if self._discord_url:
            channels.append("Discord")
        if self._smtp_host and self._smtp_user and self._smtp_to:
            channels.append("Email")
        if channels:
            logger.info(f"Alert dispatcher ready. Active channels: {', '.join(channels)}")
        else:
            logger.warning(
                "No alert channels configured! "
                "Set SLACK_WEBHOOK_URL, DISCORD_WEBHOOK_URL, or SMTP_* env vars "
                "to receive alerts outside the worker logs."
            )

    def dispatch(self, alerts: List[FiredAlert]) -> None:
        """
        Fan out a list of FiredAlert objects to every configured channel.
        Each channel failure is logged but does not block other channels.
        """
        if not alerts:
            return

        for alert in alerts:
            self._dispatch_single(alert)

    def _dispatch_single(self, alert: FiredAlert) -> None:
        # ── Slack ──────────────────────────────────────────────────────
        if self._slack_url:
            try:
                from alerting.slack import send_slack_alert
                send_slack_alert(alert, self._slack_url, self._dashboard_url)
            except Exception as exc:
                logger.error(f"Slack dispatch failed for '{alert.rule_name}': {exc}")

        # ── Discord ────────────────────────────────────────────────────
        if self._discord_url:
            try:
                from alerting.discord import send_discord_alert
                send_discord_alert(alert, self._discord_url, self._dashboard_url)
            except Exception as exc:
                logger.error(f"Discord dispatch failed for '{alert.rule_name}': {exc}")

        # ── Email ──────────────────────────────────────────────────────
        if self._smtp_host and self._smtp_user and self._smtp_to:
            try:
                from alerting.email import send_email_alert
                send_email_alert(
                    alert=alert,
                    smtp_host=self._smtp_host,
                    smtp_port=self._smtp_port,
                    smtp_username=self._smtp_user,
                    smtp_password=self._smtp_pass or "",
                    recipients=self._smtp_to,
                    sender=self._smtp_from,
                    dashboard_url=self._dashboard_url,
                )
            except Exception as exc:
                logger.error(f"Email dispatch failed for '{alert.rule_name}': {exc}")
