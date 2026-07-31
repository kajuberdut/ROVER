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


class MockVaultClient:
    def __init__(self) -> None:
        self.secrets: dict[str, dict] = {}

    def write_secret(self, path: str, secret_data: dict) -> bool:
        self.secrets[path] = secret_data
        return True

    def read_secret(self, path: str) -> dict | None:
        return self.secrets.get(path)

    def delete_secret(self, path: str) -> bool:
        self.secrets.pop(path, None)
        return True


def test_notification_destinations_crud_and_vault() -> None:
    mock_vault = MockVaultClient()

    # 1. Create Webhook destination with HMAC secret
    webhook_dest = db.add_notification_destination(
        name="Security Webhook",
        destination_type="webhook",
        scope="system",
        config_dict={"url": "https://example.com/webhook"},
        secret_value="super-secret-hmac-key",  # noqa: S106
        is_system=True,
        vault_client=mock_vault,  # type: ignore
    )
    assert webhook_dest["id"] is not None
    assert webhook_dest["name"] == "Security Webhook"
    assert webhook_dest["type"] == "webhook"
    assert webhook_dest["scope"] == "system"
    assert webhook_dest["config"]["url"] == "https://example.com/webhook"
    assert webhook_dest["vault_secret_path"] is not None

    # Check Vault contents
    secret_in_vault = db.get_destination_unmasked_secret(
        webhook_dest["id"],
        vault_client=mock_vault,  # type: ignore
    )
    assert secret_in_vault == {"secret": "super-secret-hmac-key"}

    # 2. Create SMTP destination with complex dict secret
    prod = db.add_product(name="Notification Test Product", description="Test")
    smtp_dest = db.add_notification_destination(
        name="Team SMTP",
        destination_type="smtp",
        scope="product",
        product_id=prod,
        config_dict={
            "smtp_host": "smtp.mail.com",
            "smtp_port": 587,
            "smtp_username": "alerts",
            "from_email": "alerts@mail.com",
        },
        secret_value={"password": "smtp-password-123"},
        vault_client=mock_vault,  # type: ignore
    )
    assert smtp_dest["scope"] == "product"
    assert smtp_dest["product_id"] == prod
    assert smtp_dest["config"]["smtp_host"] == "smtp.mail.com"

    smtp_vault_secret = db.get_destination_unmasked_secret(
        smtp_dest["id"],
        vault_client=mock_vault,  # type: ignore
    )
    assert smtp_vault_secret == {"password": "smtp-password-123"}

    # 3. Query destinations
    system_dests = db.get_notification_destinations(scope="system")
    assert any(d["id"] == webhook_dest["id"] for d in system_dests)

    prod_dests = db.get_notification_destinations(scope="product", product_id=prod)
    assert any(d["id"] == smtp_dest["id"] for d in prod_dests)

    # 4. Update destination
    updated_webhook = db.update_notification_destination(
        webhook_dest["id"],
        name="Updated Security Webhook",
        config_dict={"url": "https://example.com/new-webhook"},
        secret_value="new-hmac-key",  # noqa: S106
        vault_client=mock_vault,  # type: ignore
    )
    assert updated_webhook is not None
    assert updated_webhook["name"] == "Updated Security Webhook"
    assert updated_webhook["config"]["url"] == "https://example.com/new-webhook"

    new_secret_in_vault = db.get_destination_unmasked_secret(
        webhook_dest["id"],
        vault_client=mock_vault,  # type: ignore
    )
    assert new_secret_in_vault == {"secret": "new-hmac-key"}

    # 5. Delete destination
    deleted = db.delete_notification_destination(
        webhook_dest["id"],
        vault_client=mock_vault,  # type: ignore
    )
    assert deleted is True
    assert db.get_notification_destination_by_id(webhook_dest["id"]) is None
    assert webhook_dest["vault_secret_path"] not in mock_vault.secrets


def test_notification_rules_and_evaluation_engine() -> None:
    mock_vault = MockVaultClient()
    prod = db.add_product(name="Rules Test Product", description="Rule Engine Test")

    dest = db.add_notification_destination(
        name="Rule Engine Webhook",
        destination_type="webhook",
        scope="product",
        product_id=prod,
        config_dict={"url": "https://example.com/alerts"},
        vault_client=mock_vault,  # type: ignore
    )

    # 1. Add vulnerability rule (min_severity = HIGH)
    vuln_rule = db.add_notification_rule(
        destination_id=dest["id"],
        event_type=db.NotificationEventType.VULNERABILITY_FOUND,
        scope="product",
        product_id=prod,
        min_severity=db.NotificationSeverity.HIGH,
    )
    assert vuln_rule["id"] is not None
    assert vuln_rule["min_severity"] == "HIGH"

    # 2. Add EOL warning rule (eol_warning_days = 90)
    eol_rule = db.add_notification_rule(
        destination_id=dest["id"],
        event_type=db.NotificationEventType.EOL_WARNING,
        scope="product",
        product_id=prod,
        eol_warning_days=90,
    )
    assert eol_rule["eol_warning_days"] == 90

    # 3. Test Rule Querying
    product_rules = db.get_notification_rules(scope="product", product_id=prod)
    assert len(product_rules) == 2

    # 4. Evaluate vulnerability severity filtering
    # CRITICAL vulnerability -> should match
    crit_matches = db.evaluate_notification_rules(
        event_type=db.NotificationEventType.VULNERABILITY_FOUND,
        severity="CRITICAL",
        product_id=prod,
    )
    assert len(crit_matches) == 1
    assert crit_matches[0]["id"] == vuln_rule["id"]

    # HIGH vulnerability -> should match
    high_matches = db.evaluate_notification_rules(
        event_type=db.NotificationEventType.VULNERABILITY_FOUND,
        severity="HIGH",
        product_id=prod,
    )
    assert len(high_matches) == 1

    # MEDIUM vulnerability -> should be suppressed
    med_matches = db.evaluate_notification_rules(
        event_type=db.NotificationEventType.VULNERABILITY_FOUND,
        severity="MEDIUM",
        product_id=prod,
    )
    assert len(med_matches) == 0

    # 5. Evaluate EOL Lead Time filtering
    # 45 days remaining (<= 90) -> should match
    eol_45_matches = db.evaluate_notification_rules(
        event_type=db.NotificationEventType.EOL_WARNING,
        eol_days_remaining=45,
        product_id=prod,
    )
    assert len(eol_45_matches) == 1
    assert eol_45_matches[0]["id"] == eol_rule["id"]

    # 120 days remaining (> 90) -> should be suppressed
    eol_120_matches = db.evaluate_notification_rules(
        event_type=db.NotificationEventType.EOL_WARNING,
        eol_days_remaining=120,
        product_id=prod,
    )
    assert len(eol_120_matches) == 0

    # 6. Update rule (disable rule)
    updated_rule = db.update_notification_rule(vuln_rule["id"], is_enabled=False)
    assert updated_rule is not None
    assert updated_rule["is_enabled"] is False

    # Disabled rule should no longer match
    disabled_matches = db.evaluate_notification_rules(
        event_type=db.NotificationEventType.VULNERABILITY_FOUND,
        severity="CRITICAL",
        product_id=prod,
    )
    assert len(disabled_matches) == 0

    # 7. Delete rule
    deleted = db.delete_notification_rule(vuln_rule["id"])
    assert deleted is True
    assert db.get_notification_rule_by_id(vuln_rule["id"]) is None
