"""tests/test_notification_engine.py — Unit tests for Notification Dispatch Engine & Audit Logging."""

from unittest.mock import MagicMock, patch

from test_notifications import MockVaultClient

from rover import db
from rover.notifications.engine import dispatch_event


def test_dispatch_event_and_audit_logging() -> None:
    mock_vault = MockVaultClient()
    prod = db.add_product(name="Dispatch Engine Product", description="Test")

    # Create destination
    dest = db.add_notification_destination(
        name="Dispatch Engine Webhook",
        destination_type="webhook",
        scope="product",
        product_id=prod,
        config_dict={"url": "https://example.com/dispatch-target"},
        secret_value="dispatch-secret",  # noqa: S106
        vault_client=mock_vault,  # type: ignore
    )

    # Create rule
    rule = db.add_notification_rule(
        destination_id=dest["id"],
        event_type=db.NotificationEventType.VULNERABILITY_FOUND,
        scope="product",
        product_id=prod,
        min_severity=db.NotificationSeverity.HIGH,
    )

    payload = {
        "title": "High Severity Vulnerability in libssl",
        "message": "CVE-2026-9999 found in asset.",
    }

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
        results = dispatch_event(
            event_type=db.NotificationEventType.VULNERABILITY_FOUND,
            payload=payload,
            severity="HIGH",
            product_id=prod,
            vault_client=mock_vault,  # type: ignore
        )

        assert len(results) == 1
        res = results[0]
        assert res["rule_id"] == rule["id"]
        assert res["destination_id"] == dest["id"]
        assert res["status"] == "delivered"
        assert res["success"] is True

        mock_urlopen.assert_called_once()

    # Query audit logs
    logs = db.get_notification_logs(destination_id=dest["id"])
    assert len(logs) >= 1
    latest_log = logs[0]
    assert latest_log["destination_id"] == dest["id"]
    assert latest_log["rule_id"] == rule["id"]
    assert latest_log["status"] == "delivered"
    assert latest_log["http_status_code"] == 200
    assert (
        latest_log["payload"]["event_type"]
        == db.NotificationEventType.VULNERABILITY_FOUND
    )


def test_scan_completed_job_dispatch() -> None:
    mock_vault = MockVaultClient()
    prod = db.add_product(name="Job Event Product", description="Test")

    dest = db.add_notification_destination(
        name="Job Completion Target",
        destination_type="webhook",
        scope="product",
        product_id=prod,
        config_dict={"url": "https://example.com/scan-completed"},
        vault_client=mock_vault,  # type: ignore
    )

    db.add_notification_rule(
        destination_id=dest["id"],
        event_type="scan.completed",
        scope="product",
        product_id=prod,
    )

    job_id = db.create_scanner_job(
        scanner_name="trivy",
        target_url="https://github.com/example/test-repo",
        product_id=prod,
    )

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
        db.update_scanner_job_status(
            job_id=job_id,
            status="completed",
            results_json="{}",
        )
        mock_urlopen.assert_called_once()

    logs = db.get_notification_logs(destination_id=dest["id"])
    assert len(logs) >= 1
    assert logs[0]["event_type"] == "scan.completed"
    assert logs[0]["status"] == "delivered"
