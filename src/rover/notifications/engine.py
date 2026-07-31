"""src/rover/notifications/engine.py — Notification Dispatch & Rule Matching Engine."""

import logging
from typing import Any

from rover import db
from rover.notifications.transports import deliver_notification
from rover.vault import OpenBaoClient

logger = logging.getLogger(__name__)


def dispatch_event(
    event_type: str,
    payload: dict[str, Any],
    severity: str | None = None,
    eol_days_remaining: int | None = None,
    product_id: str | None = None,
    user_sub: str | None = None,
    vault_client: OpenBaoClient | None = None,
) -> list[dict[str, Any]]:
    """Evaluates incoming system event against active notification rules and dispatches alerts.

    Logs delivery attempts and status in notification_logs.

    Returns:
        List of delivery summary dictionaries for matched rules.
    """
    payload_copy = dict(payload)
    payload_copy["event_type"] = event_type
    if severity:
        payload_copy["severity"] = severity
    if product_id:
        payload_copy["product_id"] = product_id

    # 1. Evaluate matching rules
    matched_rules = db.evaluate_notification_rules(
        event_type=event_type,
        severity=severity,
        eol_days_remaining=eol_days_remaining,
        product_id=product_id,
        user_sub=user_sub,
    )

    if not matched_rules:
        logger.debug(f"No notification rules matched for event '{event_type}'.")
        return []

    results = []
    for rule in matched_rules:
        dest_id = rule["destination_id"]
        dest = db.get_notification_destination_by_id(dest_id)
        if not dest:
            logger.warning(
                f"Destination '{dest_id}' referenced by rule '{rule['id']}' not found."
            )
            continue

        # 2. Retrieve unmasked Vault secret if present
        vault_secret: dict[str, Any] | None = None
        if dest.get("vault_secret_path"):
            vault_secret = db.get_destination_unmasked_secret(
                dest_id, vault_client=vault_client
            )

        # 3. Deliver notification payload via appropriate transport
        rule_payload = dict(payload_copy)
        if rule.get("recipient_emails"):
            rule_payload["recipient_emails"] = rule["recipient_emails"]

        try:
            success = deliver_notification(
                dest, rule_payload, vault_secret=vault_secret
            )
            status = "delivered" if success else "failed"
            http_status = 200 if success else 500
            error_msg = None if success else "Transport delivery returned false"
        except Exception as e:
            logger.error(
                f"Error delivering notification rule '{rule['id']}' to destination '{dest_id}': {e}"
            )
            success = False
            status = "failed"
            http_status = 500
            error_msg = str(e)

        # 4. Audit Log delivery attempt
        log_id = db.log_notification_attempt(
            destination_id=dest_id,
            rule_id=rule["id"],
            event_type=event_type,
            status=status,
            http_status_code=http_status,
            error_message=error_msg,
            payload_dict=payload_copy,
        )

        results.append(
            {
                "rule_id": rule["id"],
                "destination_id": dest_id,
                "status": status,
                "log_id": log_id,
                "success": success,
            }
        )

    return results
