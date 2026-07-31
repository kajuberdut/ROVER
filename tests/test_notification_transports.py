"""tests/test_notification_transports.py — Unit tests for pluggable notification transports."""

import json
from unittest.mock import MagicMock, patch

from rover.notifications.transports import deliver_notification, get_transport
from rover.notifications.transports.slack import SlackTransport, format_slack_payload
from rover.notifications.transports.smtp import SmtpTransport, build_email_message
from rover.notifications.transports.webhook import (
    WebhookTransport,
    compute_hmac_signature,
)


def test_compute_hmac_signature() -> None:
    secret = "my-hmac-secret"
    payload = b'{"event":"test"}'
    sig = compute_hmac_signature(secret, payload)
    assert sig.startswith("sha256=")

    # Verify deterministic calculation
    sig2 = compute_hmac_signature(secret, payload)
    assert sig == sig2


def test_webhook_transport_delivery() -> None:
    transport = WebhookTransport()
    destination = {
        "type": "webhook",
        "config": {
            "url": "https://example.com/hooks/alert",
            "custom_headers": {"X-Custom-Env": "prod"},
        },
    }
    payload = {
        "event_type": "vulnerability.found",
        "title": "Critical Vuln in OpenSSL",
        "severity": "CRITICAL",
    }
    vault_secret = {"secret": "secret-key-123"}

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
        success = transport.deliver(destination, payload, vault_secret=vault_secret)
        assert success is True

        mock_urlopen.assert_called_once()
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == "https://example.com/hooks/alert"
        assert req.get_header("Content-type") == "application/json"
        assert req.get_header("X-custom-env") == "prod"

        sig_header = req.get_header("X-rover-signature")
        assert sig_header is not None
        assert sig_header.startswith("sha256=")

        sent_body = req.data
        expected_sig = compute_hmac_signature("secret-key-123", sent_body)
        assert sig_header == expected_sig


def test_slack_transport_delivery() -> None:
    transport = SlackTransport()
    destination = {
        "type": "slack",
        "config": {"webhook_url": "https://hooks.slack.com/services/T00/B00/X00"},
    }
    payload = {
        "event_type": "scan.completed",
        "title": "Scan Complete for ROVER Web",
        "severity": "INFO",
        "message": "Scanned 12 assets with 0 critical findings.",
    }

    formatted = format_slack_payload(payload)
    assert "blocks" in formatted
    assert formatted["text"] == "ROVER Alert: Scan Complete for ROVER Web"

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
        success = transport.deliver(destination, payload)
        assert success is True

        mock_urlopen.assert_called_once()
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == "https://hooks.slack.com/services/T00/B00/X00"
        body_json = json.loads(req.data.decode("utf-8"))
        assert body_json["text"] == "ROVER Alert: Scan Complete for ROVER Web"


def test_smtp_transport_delivery() -> None:
    transport = SmtpTransport()
    destination = {
        "type": "smtp",
        "config": {
            "smtp_host": "smtp.example.com",
            "smtp_port": 587,
            "smtp_username": "alert-user",
            "from_email": "rover@example.com",
            "to_email": "security-team@example.com",
            "encryption": "starttls",
        },
    }
    payload = {
        "event_type": "eol.warning",
        "title": "EOL Advance Warning: Python 3.8",
        "message": "Python 3.8 reaches EOL in 60 days.",
    }
    vault_secret = {"smtp_password": "smtp-password-xyz"}

    mock_msg = build_email_message(
        "rover@example.com",
        "security-team@example.com",
        "EOL Advance Warning: Python 3.8",
        "Python 3.8 reaches EOL in 60 days.",
    )
    assert mock_msg["Subject"] == "EOL Advance Warning: Python 3.8"

    mock_smtp_instance = MagicMock()
    with patch("smtplib.SMTP", return_value=mock_smtp_instance) as mock_smtp_cls:
        success = transport.deliver(destination, payload, vault_secret=vault_secret)
        assert success is True

        mock_smtp_cls.assert_called_once_with("smtp.example.com", 587, timeout=10)
        mock_smtp_instance.starttls.assert_called_once()
        mock_smtp_instance.login.assert_called_once_with(
            "alert-user", "smtp-password-xyz"
        )
        mock_smtp_instance.sendmail.assert_called_once()
        mock_smtp_instance.quit.assert_called_once()


def test_deliver_notification_registry() -> None:
    dest_webhook = {"type": "webhook", "config": {"url": "https://test.com"}}
    dest_slack = {"type": "slack", "config": {"webhook_url": "https://slack.com"}}

    assert get_transport("webhook") is not None
    assert get_transport("slack") is not None
    assert get_transport("unknown") is None

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        res1 = deliver_notification(
            dest_webhook, {"event_type": "test", "title": "Test"}
        )
        assert res1 is True

        res2 = deliver_notification(dest_slack, {"event_type": "test", "title": "Test"})
        assert res2 is True
