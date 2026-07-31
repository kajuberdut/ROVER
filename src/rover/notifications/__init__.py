"""src/rover/notifications — Event-Driven Notification Engine for ROVER."""

from rover.notifications.engine import dispatch_event
from rover.notifications.transports import (
    AwsSesTransport,
    BaseTransport,
    SlackTransport,
    SmtpTransport,
    WebhookTransport,
    deliver_notification,
    get_transport,
)

__all__ = [
    "dispatch_event",
    "deliver_notification",
    "get_transport",
    "BaseTransport",
    "WebhookTransport",
    "SlackTransport",
    "SmtpTransport",
    "AwsSesTransport",
]
