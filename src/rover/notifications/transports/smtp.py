"""src/rover/notifications/transports/smtp.py — SMTP Email Notification Transport."""

import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

from rover.notifications.transports.base import BaseTransport

logger = logging.getLogger(__name__)


def build_email_message(
    from_addr: str, to_addr: str, subject: str, message_text: str
) -> MIMEMultipart:
    """Constructs a MIME email message."""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_addr

    text_part = MIMEText(message_text, "plain", "utf-8")
    msg.attach(text_part)

    # Basic HTML formatting fallback
    html_content = f"""
    <html>
      <body>
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e2e8f0; border-radius: 8px;">
          <h2 style="color: #0f172a; border-bottom: 2px solid #3b82f6; padding-bottom: 8px;">🛡️ {subject}</h2>
          <pre style="background: #f8fafc; padding: 12px; border-radius: 4px; font-family: monospace; white-space: pre-wrap;">{message_text}</pre>
          <hr style="border: none; border-top: 1px solid #e2e8f0; margin-top: 20px;" />
          <p style="font-size: 12px; color: #64748b;">Sent automatically by R.O.V.E.R. Notification Engine.</p>
        </div>
      </body>
    </html>
    """
    html_part = MIMEText(html_content, "html", "utf-8")
    msg.attach(html_part)

    return msg


class SmtpTransport(BaseTransport):
    """SMTP Email Transport Adapter."""

    def deliver(
        self,
        destination: dict[str, Any],
        payload: dict[str, Any],
        vault_secret: dict[str, Any] | None = None,
    ) -> bool:
        config = destination.get("config", {})
        smtp_host = config.get("smtp_host") or config.get("host")
        if not smtp_host:
            logger.error(
                "SmtpTransport delivery failed: 'smtp_host' missing in config."
            )
            return False

        smtp_port = int(config.get("smtp_port") or config.get("port") or 587)
        smtp_user = config.get("smtp_username") or config.get("username")
        from_email = config.get("from_email")
        if not from_email or "@" not in str(from_email):
            if smtp_user and "@" in str(smtp_user):
                from_email = smtp_user
            else:
                from_email = "rover@rover.local"
        to_emails_raw = (
            payload.get("to_email")
            or payload.get("recipient_emails")
            or payload.get("recipient_email")
            or config.get("to_email")
            or config.get("recipient")
            or from_email
        )
        if not to_emails_raw:
            logger.error("SmtpTransport delivery failed: no recipient emails provided.")
            return False

        if isinstance(to_emails_raw, str):
            to_emails = [e.strip() for e in to_emails_raw.split(",") if e.strip()]
        elif isinstance(to_emails_raw, list):
            to_emails = [str(e).strip() for e in to_emails_raw if str(e).strip()]
        else:
            to_emails = []

        if not to_emails:
            logger.error("SmtpTransport delivery failed: empty recipient email list.")
            return False

        password: str | None = None
        if vault_secret:
            password = vault_secret.get("smtp_password") or vault_secret.get("password")
        if not password:
            password = config.get("smtp_password") or config.get("password")

        encryption = (config.get("encryption") or "starttls").lower()

        title = (
            payload.get("title")
            or f"ROVER Alert: {payload.get('event_type', 'Notification')}"
        )
        message_text = payload.get("message") or str(payload)

        msg = build_email_message(from_email, ", ".join(to_emails), title, message_text)

        try:
            if encryption == "tls" or smtp_port == 465:
                server: smtplib.SMTP = smtplib.SMTP_SSL(
                    smtp_host, smtp_port, timeout=10
                )
            else:
                server = smtplib.SMTP(smtp_host, smtp_port, timeout=10)
                if encryption != "none" and server.has_extn("starttls"):
                    server.starttls()

            if smtp_user and password:
                server.login(smtp_user, password)

            server.sendmail(from_email, to_emails, msg.as_string())
            server.quit()
            return True
        except Exception as e:
            logger.error(
                f"SmtpTransport delivery failed for {to_emails} via {smtp_host}: {e}"
            )
            return False
