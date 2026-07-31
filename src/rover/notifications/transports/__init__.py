"""src/rover/notifications/transports/__init__.py — Transport Registry and Dispatch Helpers."""

import logging
from typing import Any

from rover.notifications.transports.aws_ses import AwsSesTransport
from rover.notifications.transports.base import BaseTransport
from rover.notifications.transports.slack import SlackTransport
from rover.notifications.transports.smtp import SmtpTransport
from rover.notifications.transports.webhook import WebhookTransport

logger = logging.getLogger(__name__)

_TRANSPORTS: dict[str, BaseTransport] = {
    "webhook": WebhookTransport(),
    "slack": SlackTransport(),
    "teams": SlackTransport(),  # MS Teams supported via webhook format
    "smtp": SmtpTransport(),
    "email": SmtpTransport(),
    "aws_ses": AwsSesTransport(),
    "ses": AwsSesTransport(),
}


def get_transport(destination_type: str) -> BaseTransport | None:
    """Returns the transport adapter instance for a destination type string."""
    return _TRANSPORTS.get((destination_type or "").lower())


def deliver_notification(
    destination: dict[str, Any],
    payload: dict[str, Any],
    vault_secret: dict[str, Any] | None = None,
) -> bool:
    """Dispatches a notification payload using the appropriate transport for the destination."""
    dest_type = destination.get("type", "webhook")
    transport = get_transport(dest_type)
    if not transport:
        logger.error(
            f"No transport adapter registered for destination type '{dest_type}'."
        )
        return False
    return transport.deliver(destination, payload, vault_secret=vault_secret)


__all__ = [
    "BaseTransport",
    "WebhookTransport",
    "SlackTransport",
    "SmtpTransport",
    "AwsSesTransport",
    "get_transport",
    "deliver_notification",
]
