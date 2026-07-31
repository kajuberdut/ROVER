"""src/rover/notifications/transports/slack.py — Slack & MS Teams Block Kit Notification Transport."""

import json
import logging
import urllib.error
import urllib.request
from typing import Any

from rover.notifications.transports.base import BaseTransport

logger = logging.getLogger(__name__)


def format_slack_payload(event_payload: dict[str, Any]) -> dict[str, Any]:
    """Formats a ROVER event payload into a Slack Block Kit message structure."""
    event_type = event_payload.get("event_type", "notification")
    title = event_payload.get("title") or f"ROVER Alert: {event_type}"
    message = event_payload.get("message") or ""
    severity = event_payload.get("severity") or "INFO"
    product_name = event_payload.get("product_name") or "ROVER"

    color_map = {
        "CRITICAL": "#E11D48",  # Red
        "HIGH": "#F97316",  # Orange
        "MEDIUM": "#FBBF24",  # Yellow
        "LOW": "#3B82F6",  # Blue
        "INFO": "#10B981",  # Green
    }
    color = color_map.get(severity.upper(), "#6B7280")

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"🛡️ {title}",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Event:* `{event_type}`"},
                {"type": "mrkdwn", "text": f"*Severity:* `{severity}`"},
                {"type": "mrkdwn", "text": f"*Product:* `{product_name}`"},
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": message,
            },
        },
    ]

    return {
        "text": f"ROVER Alert: {title}",
        "blocks": blocks,
        "attachments": [{"color": color, "blocks": []}],
    }


class SlackTransport(BaseTransport):
    """Slack & MS Teams Transport Adapter for webhook delivery."""

    def deliver(
        self,
        destination: dict[str, Any],
        payload: dict[str, Any],
        vault_secret: dict[str, Any] | None = None,
    ) -> bool:
        config = destination.get("config", {})
        webhook_url = config.get("webhook_url") or config.get("url")
        if not webhook_url and vault_secret:
            webhook_url = vault_secret.get("webhook_url") or vault_secret.get("url")

        if not webhook_url:
            logger.error(
                "SlackTransport delivery failed: 'webhook_url' missing in config and Vault secret."
            )
            return False

        slack_body = format_slack_payload(payload)
        body_bytes = json.dumps(slack_body).encode("utf-8")
        headers = {"Content-Type": "application/json"}

        req = urllib.request.Request(  # noqa: S310
            webhook_url, data=body_bytes, headers=headers, method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                return bool(200 <= resp.status < 300)
        except Exception as e:
            logger.error(f"SlackTransport delivery failed for {webhook_url}: {e}")
            return False
