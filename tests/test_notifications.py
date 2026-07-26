"""tests/test_notifications.py: Unit tests for system admin notifications queue and Trivy update notice parser."""

from unittest.mock import patch

from rover import db
from rover.plugins.trivy import _check_and_raise_trivy_notices


def test_create_and_get_admin_notifications() -> None:
    # Create notification with metadata_dict
    notif_id = db.create_admin_notification(
        title="Trivy Scanner Update Available (v0.72.0)",
        message="Version 0.72.0 of Trivy is now available. The current version running in ROVER is 0.69.3.",
        category="scanner_update",
        source_tool="trivy",
        metadata_dict={"current_version": "0.69.3", "available_version": "0.72.0"},
    )
    assert notif_id is not None

    # Deduplication test: duplicate un-dismissed creation returns None
    dup_id = db.create_admin_notification(
        title="Trivy Scanner Update Available (v0.72.0)",
        message="Duplicate message",
        category="scanner_update",
        source_tool="trivy",
        metadata_dict={"current_version": "0.69.3", "available_version": "0.72.0"},
    )
    assert dup_id is None

    active = db.get_active_admin_notifications()
    assert len(active) >= 1
    found = next((n for n in active if n["id"] == notif_id), None)
    assert found is not None
    assert found["source_tool"] == "trivy"
    assert found["metadata"]["available_version"] == "0.72.0"
    assert found["metadata"]["current_version"] == "0.69.3"

    # Dismiss notification
    db.dismiss_admin_notification(notif_id)
    active_after = db.get_active_admin_notifications()
    assert not any(n["id"] == notif_id for n in active_after)


def test_trivy_log_notice_parser() -> None:
    stdout = """
2026-07-25T10:00:00Z INFO Need to update DB
2026-07-25T10:00:01Z INFO DB update completed
"""
    stderr = """
📣 Notices:
  - Version 0.72.0 of Trivy is now available, current version is 0.69.3.
"""
    with patch("rover.db.create_admin_notification") as mock_create:
        _check_and_raise_trivy_notices(stdout, stderr)
        mock_create.assert_called_once_with(
            title="Trivy Scanner Update Available (v0.72.0)",
            message="Version 0.72.0 of Trivy is now available. The current version running in ROVER is 0.69.3.",
            category="scanner_update",
            source_tool="trivy",
            metadata_dict={
                "current_version": "0.69.3",
                "available_version": "0.72.0",
            },
        )
