"""src/rover/db/notification_rules.py — Database operations and Rule Engine with EOL Lead Times."""

import uuid
from enum import StrEnum
from typing import Any

from sqlalchemy import delete, select, update
from sqlalchemy.sql import func

from rover.db.connection import get_db_connection
from rover.db.schema import notification_rule_recipients, notification_rules, users


class NotificationEventType(StrEnum):
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    VULNERABILITY_FOUND = "vulnerability.found"
    EOL_WARNING = "eol.warning"


class NotificationSeverity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    ALL = "ALL"


SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "ALL": 0,
}


def set_rule_recipients(
    rule_id: str,
    user_subs: list[str] | None = None,
    emails: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Replaces all recipient entries for a notification rule in notification_rule_recipients."""
    user_subs = user_subs or []
    emails = emails or []

    with get_db_connection() as conn:
        conn.execute(
            delete(notification_rule_recipients).where(
                notification_rule_recipients.c.rule_id == rule_id
            )
        )

        for sub in set(user_subs):
            if sub:
                conn.execute(
                    notification_rule_recipients.insert().values(
                        id=str(uuid.uuid4()),
                        rule_id=rule_id,
                        recipient_type="user",
                        user_sub=sub,
                    )
                )

        for em in set(emails):
            em_clean = em.strip()
            if em_clean and "@" in em_clean:
                conn.execute(
                    notification_rule_recipients.insert().values(
                        id=str(uuid.uuid4()),
                        rule_id=rule_id,
                        recipient_type="email",
                        email=em_clean,
                    )
                )

    return get_rule_recipients(rule_id)


def get_rule_recipients(rule_id: str) -> list[dict[str, Any]]:
    """Retrieves all recipient records for a rule, including user email resolution."""
    with get_db_connection() as conn:
        stmt = (
            select(
                notification_rule_recipients,
                users.c.email.label("user_email"),
                users.c.name.label("user_name"),
            )
            .outerjoin(users, notification_rule_recipients.c.user_sub == users.c.sub)
            .where(notification_rule_recipients.c.rule_id == rule_id)
        )
        rows = conn.execute(stmt).fetchall()
        results = []
        for r in rows:
            d = dict(r._mapping)
            results.append(d)
        return results


def get_rule_recipient_emails(rule_id: str) -> list[str]:
    """Returns a list of resolved email addresses for a given rule_id."""
    recipients = get_rule_recipients(rule_id)
    emails = []
    for r in recipients:
        if r.get("recipient_type") == "user":
            em = r.get("user_email")
        else:
            em = r.get("email")
        if em and em not in emails:
            emails.append(em)
    return emails


def add_notification_rule(
    destination_id: str,
    event_type: str,
    scope: str,
    min_severity: str = "ALL",
    eol_warning_days: int | None = None,
    user_sub: str | None = None,
    product_id: str | None = None,
    is_enabled: bool = True,
    recipient_user_subs: list[str] | None = None,
    recipient_emails: list[str] | None = None,
) -> dict[str, Any]:
    """Creates a new notification rule associated with a destination and populates recipients."""
    rule_id = str(uuid.uuid4())
    with get_db_connection() as conn:
        conn.execute(
            notification_rules.insert().values(
                id=rule_id,
                destination_id=destination_id,
                event_type=event_type,
                min_severity=min_severity.upper(),
                eol_warning_days=eol_warning_days,
                scope=scope,
                user_sub=user_sub if scope == "user" else None,
                product_id=product_id if scope == "product" else None,
                is_enabled=is_enabled,
            )
        )

    user_subs = recipient_user_subs or ([user_sub] if user_sub else [])
    emails = recipient_emails or []
    set_rule_recipients(rule_id, user_subs=user_subs, emails=emails)

    res = get_notification_rule_by_id(rule_id)
    if res is None:
        raise RuntimeError(f"Failed to retrieve newly created rule {rule_id}")
    return res


def get_notification_rules(
    scope: str | None = None,
    product_id: str | None = None,
    user_sub: str | None = None,
    event_type: str | None = None,
    destination_id: str | None = None,
) -> list[dict[str, Any]]:
    """Returns notification rules matching optional filters."""
    with get_db_connection() as conn:
        stmt = select(notification_rules)
        if scope:
            stmt = stmt.where(notification_rules.c.scope == scope)
        if product_id:
            stmt = stmt.where(notification_rules.c.product_id == product_id)
        if user_sub:
            stmt = stmt.where(notification_rules.c.user_sub == user_sub)
        if event_type:
            stmt = stmt.where(notification_rules.c.event_type == event_type)
        if destination_id:
            stmt = stmt.where(notification_rules.c.destination_id == destination_id)

        stmt = stmt.order_by(notification_rules.c.created_at.desc())
        rows = conn.execute(stmt).fetchall()
        results = []
        for r in rows:
            d = dict(r._mapping)
            d["recipients"] = get_rule_recipients(d["id"])
            d["recipient_emails"] = get_rule_recipient_emails(d["id"])
            results.append(d)
        return results


def get_notification_rule_by_id(rule_id: str) -> dict[str, Any] | None:
    """Retrieves a single notification rule by ID."""
    with get_db_connection() as conn:
        row = conn.execute(
            select(notification_rules).where(notification_rules.c.id == rule_id)
        ).fetchone()
        if not row:
            return None
        d = dict(row._mapping)
        d["recipients"] = get_rule_recipients(d["id"])
        d["recipient_emails"] = get_rule_recipient_emails(d["id"])
        return d


def update_notification_rule(
    rule_id: str,
    event_type: str | None = None,
    min_severity: str | None = None,
    eol_warning_days: int | None = None,
    is_enabled: bool | None = None,
) -> dict[str, Any] | None:
    """Updates fields of an existing notification rule."""
    values: dict[str, Any] = {"updated_at": func.current_timestamp()}
    if event_type is not None:
        values["event_type"] = event_type
    if min_severity is not None:
        values["min_severity"] = min_severity.upper()
    if eol_warning_days is not None:
        values["eol_warning_days"] = eol_warning_days
    if is_enabled is not None:
        values["is_enabled"] = is_enabled

    with get_db_connection() as conn:
        conn.execute(
            update(notification_rules)
            .where(notification_rules.c.id == rule_id)
            .values(**values)
        )

    return get_notification_rule_by_id(rule_id)


def delete_notification_rule(rule_id: str) -> bool:
    """Deletes a notification rule by ID."""
    rule = get_notification_rule_by_id(rule_id)
    if not rule:
        return False

    with get_db_connection() as conn:
        conn.execute(
            delete(notification_rules).where(notification_rules.c.id == rule_id)
        )
    return True


def evaluate_notification_rules(
    event_type: str,
    severity: str | None = None,
    eol_days_remaining: int | None = None,
    product_id: str | None = None,
    user_sub: str | None = None,
) -> list[dict[str, Any]]:
    """Evaluates incoming system events against enabled rules.

    Matches rules by scope, severity threshold, and EOL lead time threshold.
    """
    with get_db_connection() as conn:
        stmt = select(notification_rules).where(
            notification_rules.c.event_type == event_type,
            notification_rules.c.is_enabled.is_(True),
        )
        rows = conn.execute(stmt).fetchall()

    matching_rules = []
    event_sev_rank = SEVERITY_ORDER.get((severity or "").upper(), 0)

    for r in rows:
        rule = dict(r._mapping)

        # 1. Scope check
        rule_scope = rule.get("scope")
        if (
            rule_scope == "product"
            and product_id
            and rule.get("product_id") != product_id
        ):
            continue
        if rule_scope == "user" and user_sub and rule.get("user_sub") != user_sub:
            continue

        # 2. Minimum Severity Check
        rule_min_sev = (rule.get("min_severity") or "ALL").upper()
        rule_sev_rank = SEVERITY_ORDER.get(rule_min_sev, 0)
        if rule_min_sev != "ALL" and event_sev_rank < rule_sev_rank:
            continue

        # 3. EOL Lead Time Check
        if event_type == NotificationEventType.EOL_WARNING:
            rule_warning_days = rule.get("eol_warning_days")
            if (
                eol_days_remaining is None
                or rule_warning_days is None
                or eol_days_remaining > rule_warning_days
            ):
                continue

        matching_rules.append(rule)

    return matching_rules
