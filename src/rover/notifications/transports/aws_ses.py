"""src/rover/notifications/transports/aws_ses.py — AWS SES Email Notification Transport."""

import logging
from typing import Any

from rover.notifications.transports.base import BaseTransport
from rover.notifications.transports.smtp import SmtpTransport

logger = logging.getLogger(__name__)


class AwsSesTransport(BaseTransport):
    """AWS SES Transport Adapter supporting boto3 client or SES SMTP endpoint fallback."""

    def deliver(
        self,
        destination: dict[str, Any],
        payload: dict[str, Any],
        vault_secret: dict[str, Any] | None = None,
    ) -> bool:
        config = destination.get("config", {})
        region = config.get("region") or "us-east-1"
        from_email = config.get("from_email")
        to_email = config.get("to_email") or config.get("recipient")

        if not from_email or not to_email:
            logger.error(
                "AwsSesTransport delivery failed: 'from_email' or 'to_email' missing in config."
            )
            return False

        aws_access_key_id: str | None = None
        aws_secret_access_key: str | None = None
        if vault_secret:
            aws_access_key_id = vault_secret.get(
                "aws_access_key_id"
            ) or vault_secret.get("access_key")
            aws_secret_access_key = vault_secret.get(
                "aws_secret_access_key"
            ) or vault_secret.get("secret_key")

        if not aws_access_key_id:
            aws_access_key_id = config.get("aws_access_key_id")
        if not aws_secret_access_key:
            aws_secret_access_key = config.get("aws_secret_access_key")

        # 1. Attempt delivery via boto3 if available
        try:
            import boto3  # type: ignore[import-not-found]

            client = boto3.client(
                "ses",
                region_name=region,
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
            )

            title = (
                payload.get("title")
                or f"ROVER Alert: {payload.get('event_type', 'Notification')}"
            )
            message_text = payload.get("message") or str(payload)

            response = client.send_email(
                Source=from_email,
                Destination={"ToAddresses": [to_email]},
                Message={
                    "Subject": {"Data": title, "Charset": "UTF-8"},
                    "Body": {"Text": {"Data": message_text, "Charset": "UTF-8"}},
                },
            )
            return bool(response.get("MessageId"))
        except ImportError:
            logger.info(
                "boto3 not installed; falling back to SES SMTP delivery endpoint."
            )
        except Exception as e:
            logger.warning(f"AWS SES boto3 delivery failed: {e}; falling back to SMTP.")

        # 2. Fallback to SES SMTP endpoint (email-smtp.<region>.amazonaws.com)
        ses_smtp_host = f"email-smtp.{region}.amazonaws.com"
        smtp_dest = {
            "config": {
                "smtp_host": ses_smtp_host,
                "smtp_port": 587,
                "smtp_username": aws_access_key_id,
                "from_email": from_email,
                "to_email": to_email,
                "encryption": "starttls",
            }
        }
        smtp_secret = {"smtp_password": aws_secret_access_key}
        return SmtpTransport().deliver(smtp_dest, payload, vault_secret=smtp_secret)
