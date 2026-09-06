"""
worker/alerting/email.py

Sends a FiredAlert via SMTP as a plain-text + HTML multipart email.
Designed to work with any SMTP provider: Gmail (app password), SendGrid
SMTP relay, AWS SES, or a self-hosted Postfix server.

Required env vars:
    SMTP_HOST       — e.g. smtp.gmail.com
    SMTP_PORT       — e.g. 587 (STARTTLS) or 465 (SSL)
    SMTP_USERNAME   — e.g. alerts@yourcompany.com
    SMTP_PASSWORD   — app password or API key
    SMTP_FROM       — sender address  (defaults to SMTP_USERNAME)
    SMTP_TO         — comma-separated recipient list
                      e.g. "security@yourcompany.com,cto@yourcompany.com"
"""

from __future__ import annotations

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List, Optional

from detection.models import FiredAlert, Severity
from utils.logger import setup_logger

logger = setup_logger("alerting.email")

_SEVERITY_HEX: dict[Severity, str] = {
    Severity.LOW:      "#2196F3",
    Severity.MEDIUM:   "#FF9800",
    Severity.HIGH:     "#F44336",
    Severity.CRITICAL: "#7B1FA2",
}


def _build_html(alert: FiredAlert, dashboard_url: Optional[str] = None) -> str:
    """Generate an HTML email body for the alert."""
    color = _SEVERITY_HEX.get(alert.severity, "#607D8B")

    ctx_rows = "".join(
        f"<tr><td style='padding:4px 8px;color:#888;'>{k.replace('_', ' ').title()}</td>"
        f"<td style='padding:4px 8px;font-family:monospace;'>{v}</td></tr>"
        for k, v in alert.context.items()
        if v is not None
    )

    investigate_btn = ""
    if dashboard_url:
        investigate_btn = (
            f"<p style='margin-top:24px;'>"
            f"<a href='{dashboard_url}/threats' style='background:{color};color:#fff;"
            f"padding:10px 20px;border-radius:4px;text-decoration:none;font-weight:bold;'>"
            f"Investigate in Sysmon →</a></p>"
        )

    return f"""
    <html><body style="font-family:Arial,sans-serif;background:#f5f5f5;padding:20px;">
    <div style="max-width:600px;margin:0 auto;background:#fff;border-radius:8px;
                border-left:6px solid {color};box-shadow:0 2px 8px rgba(0,0,0,0.1);">
        <div style="padding:20px 24px;border-bottom:1px solid #eee;">
            <h2 style="margin:0;color:{color};">⚠️ Sysmon Alert: {alert.rule_name.replace('_', ' ').title()}</h2>
            <p style="margin:4px 0 0;color:#555;">{alert.severity.value} severity on agent
               <code>{alert.agent_id}</code></p>
        </div>
        <div style="padding:20px 24px;">
            <p style="margin:0 0 12px;"><strong>Summary:</strong> {alert.message}</p>
            <table style="width:100%;border-collapse:collapse;margin-top:8px;">
                <tr><td style='padding:4px 8px;color:#888;'>Rule</td>
                    <td style='padding:4px 8px;font-family:monospace;'>{alert.rule_name}</td></tr>
                <tr><td style='padding:4px 8px;color:#888;'>Severity</td>
                    <td style='padding:4px 8px;font-family:monospace;'>{alert.severity.value}</td></tr>
                <tr><td style='padding:4px 8px;color:#888;'>Agent</td>
                    <td style='padding:4px 8px;font-family:monospace;'>{alert.agent_id}</td></tr>
                <tr><td style='padding:4px 8px;color:#888;'>Time (UTC)</td>
                    <td style='padding:4px 8px;font-family:monospace;'>{alert.triggered_at.strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
                {ctx_rows}
            </table>
            {investigate_btn}
        </div>
        <div style="padding:12px 24px;background:#f9f9f9;border-top:1px solid #eee;
                    color:#aaa;font-size:12px;">
            Sysmon Security Platform — open-source threat detection for startups
        </div>
    </div>
    </body></html>
    """


def send_email_alert(
    alert: FiredAlert,
    smtp_host: str,
    smtp_port: int,
    smtp_username: str,
    smtp_password: str,
    recipients: List[str],
    sender: Optional[str] = None,
    dashboard_url: Optional[str] = None,
    use_tls: bool = True,
) -> bool:
    """
    Send an HTML + plaintext alert email via SMTP.

    Returns True on success, False on any error.
    """
    if not recipients:
        logger.warning("Email alert skipped: no recipients configured (SMTP_TO).")
        return False

    sender = sender or smtp_username
    subject = f"[Sysmon {alert.severity.value}] {alert.rule_name.replace('_', ' ').title()} on {alert.agent_id}"

    # Plain-text fallback
    plain = (
        f"Sysmon Security Alert\n"
        f"{'=' * 40}\n"
        f"Rule:     {alert.rule_name}\n"
        f"Severity: {alert.severity.value}\n"
        f"Agent:    {alert.agent_id}\n"
        f"Time:     {alert.triggered_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n"
        f"Summary: {alert.message}\n\n"
        f"Context:\n" +
        "\n".join(f"  {k}: {v}" for k, v in alert.context.items())
    )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = sender
    msg["To"]      = ", ".join(recipients)
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(_build_html(alert, dashboard_url), "html"))

    try:
        if use_tls:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                server.ehlo()
                server.starttls()
                server.login(smtp_username, smtp_password)
                server.sendmail(sender, recipients, msg.as_string())
        else:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10) as server:
                server.login(smtp_username, smtp_password)
                server.sendmail(sender, recipients, msg.as_string())

        logger.info(
            f"Email alert sent to {recipients} for rule '{alert.rule_name}'."
        )
        return True

    except smtplib.SMTPException as exc:
        logger.error(f"SMTP error sending alert email: {exc}")
        return False
    except OSError as exc:
        logger.error(f"Network error sending alert email: {exc}")
        return False
