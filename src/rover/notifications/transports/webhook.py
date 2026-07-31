"""src/rover/notifications/transports/webhook.py — Webhook Transport with HMAC-SHA256 Signatures."""

import hashlib
import hmac
import json
import logging
import urllib.error
import urllib.request
from typing import Any

from rover.notifications.transports.base import BaseTransport

logger = logging.getLogger(__name__)


def compute_hmac_signature(secret: str, body_bytes: bytes) -> str:
    """Computes HMAC-SHA256 hex digest for payload signing."""
    mac = hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


class WebhookTransport(BaseTransport):
    """Webhook Transport Adapter for HTTP POST delivery with HMAC-SHA256 signatures."""

    def deliver(
        self,
        destination: dict[str, Any],
        payload: dict[str, Any],
        vault_secret: dict[str, Any] | None = None,
    ) -> bool:
        config = destination.get("config", {})
        url = config.get("url")
        if not url:
            logger.error("WebhookTransport delivery failed: 'url' missing in config.")
            return False

        secret_val: str | None = None
        if vault_secret:
            secret_val = vault_secret.get("secret") or vault_secret.get(
                "webhook_secret"
            )
        if not secret_val:
            secret_val = config.get("secret")

        body_bytes = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}

        if secret_val:
            sig = compute_hmac_signature(secret_val, body_bytes)
            headers["X-Rover-Signature"] = sig

        custom_headers = config.get("custom_headers") or {}
        if isinstance(custom_headers, dict):
            for k, v in custom_headers.items():
                headers[str(k)] = str(v)

        req = urllib.request.Request(  # noqa: S310
            url, data=body_bytes, headers=headers, method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                return bool(200 <= resp.status < 300)
        except Exception as e:
            logger.error(f"WebhookTransport delivery failed for {url}: {e}")
            return False
