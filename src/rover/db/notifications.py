"""rover/db/notifications.py: Database helpers for system admin notifications queue."""

import json
import uuid
from typing import Any

from sqlalchemy import insert, select, update
from sqlalchemy.sql import func

from rover.db.connection import get_db_connection
from rover.db.schema import admin_notifications


def create_admin_notification(
    title: str,
    message: str,
    category: str = "scanner_update",
    source_tool: str = "trivy",
    metadata_dict: dict[str, Any] | None = None,
) -> str | None:
    """Creates a new admin notification if an active (un-dismissed) notification

    with the exact same title, source_tool, and category does not already exist.
    """
    metadata_json = json.dumps(metadata_dict or {})

    with get_db_connection() as conn:
        # Deduplication check: avoid creating duplicate un-dismissed notifications
        existing = conn.execute(
            select(admin_notifications.c.id).where(
                admin_notifications.c.source_tool == source_tool,
                admin_notifications.c.category == category,
                admin_notifications.c.title == title,
                admin_notifications.c.is_dismissed.is_(False),
            )
        ).fetchone()

        if existing:
            return None

        notif_id = str(uuid.uuid4())
        conn.execute(
            insert(admin_notifications).values(
                id=notif_id,
                title=title,
                message=message,
                category=category,
                source_tool=source_tool,
                metadata_json=metadata_json,
                is_dismissed=False,
            )
        )
        return notif_id


def get_active_admin_notifications() -> list[dict[str, Any]]:
    """Returns all active (un-dismissed) system admin notifications ordered by created_at DESC."""
    with get_db_connection() as conn:
        rows = conn.execute(
            select(admin_notifications)
            .where(admin_notifications.c.is_dismissed.is_(False))
            .order_by(admin_notifications.c.created_at.desc())
        ).fetchall()
        results = []
        for row in rows:
            data = dict(row._mapping)
            m_raw = data.get("metadata_json")
            if isinstance(m_raw, (dict, list)):
                data["metadata"] = m_raw
            elif isinstance(m_raw, (str, bytes)):
                try:
                    data["metadata"] = json.loads(m_raw)
                except Exception:
                    data["metadata"] = {}
            else:
                data["metadata"] = {}
            results.append(data)
        return results


def get_all_admin_notifications(limit: int = 50) -> list[dict[str, Any]]:
    """Returns both active and dismissed notifications for history/log viewing."""
    with get_db_connection() as conn:
        rows = conn.execute(
            select(admin_notifications)
            .order_by(admin_notifications.c.created_at.desc())
            .limit(limit)
        ).fetchall()
        results = []
        for row in rows:
            data = dict(row._mapping)
            m_raw = data.get("metadata_json")
            if isinstance(m_raw, (dict, list)):
                data["metadata"] = m_raw
            elif isinstance(m_raw, (str, bytes)):
                try:
                    data["metadata"] = json.loads(m_raw)
                except Exception:
                    data["metadata"] = {}
            else:
                data["metadata"] = {}
            results.append(data)
        return results


def dismiss_admin_notification(notification_id: str) -> None:
    """Marks an admin notification as dismissed."""
    with get_db_connection() as conn:
        conn.execute(
            update(admin_notifications)
            .where(admin_notifications.c.id == notification_id)
            .values(is_dismissed=True, dismissed_at=func.current_timestamp())
        )


def restore_admin_notification(notification_id: str) -> None:
    """Restores a dismissed admin notification back to active status."""
    with get_db_connection() as conn:
        conn.execute(
            update(admin_notifications)
            .where(admin_notifications.c.id == notification_id)
            .values(is_dismissed=False, dismissed_at=None)
        )
