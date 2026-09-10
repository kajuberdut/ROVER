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


def get_admin_notifications_count() -> int:
    """Returns total count of admin notifications recorded in the system."""
    with get_db_connection() as conn:
        return (
            conn.execute(select(func.count()).select_from(admin_notifications)).scalar()
            or 0
        )


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


def get_paginated_admin_notifications(
    page: int = 1, page_size: int = 10
) -> dict[str, Any]:
    """Returns paginated admin notifications (both active and dismissed) for history/log viewing."""
    import math

    page = max(1, page)
    page_size = max(1, min(100, page_size))
    offset = (page - 1) * page_size

    with get_db_connection() as conn:
        total = (
            conn.execute(select(func.count()).select_from(admin_notifications)).scalar()
            or 0
        )

        rows = conn.execute(
            select(admin_notifications)
            .order_by(admin_notifications.c.created_at.desc())
            .offset(offset)
            .limit(page_size)
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

            for k, v in list(data.items()):
                if hasattr(v, "isoformat"):
                    data[k] = v.isoformat()

            results.append(data)

        total_pages = max(1, math.ceil(total / page_size)) if total > 0 else 1

        return {
            "items": results,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
        }


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


def dismiss_outdated_scanner_notifications(
    source_tool: str, current_version: str
) -> None:
    """Dismisses active scanner update notifications for `source_tool` when configured image version >= available version."""
    import re

    def _parse_semver(v_str: str) -> tuple[int, int, int]:
        cleaned = re.sub(r"^[vV]", "", v_str.strip())
        match = re.search(r"(\d+)\.(\d+)\.(\d+)", cleaned)
        if match:
            return (int(match.group(1)), int(match.group(2)), int(match.group(3)))
        return (0, 0, 0)

    curr_tuple = _parse_semver(current_version)
    if curr_tuple == (0, 0, 0):
        return

    with get_db_connection() as conn:
        active_notifs = conn.execute(
            select(admin_notifications).where(
                admin_notifications.c.source_tool == source_tool,
                admin_notifications.c.category == "scanner_update",
                admin_notifications.c.is_dismissed.is_(False),
            )
        ).fetchall()

        for notif in active_notifs:
            m_raw = notif._mapping.get("metadata_json")
            metadata = {}
            if isinstance(m_raw, (str, bytes)):
                try:
                    metadata = json.loads(m_raw)
                except Exception:  # noqa: S110
                    pass
            elif isinstance(m_raw, dict):
                metadata = m_raw

            avail_v = metadata.get("available_version")
            if avail_v:
                avail_tuple = _parse_semver(avail_v)
                if curr_tuple >= avail_tuple and avail_tuple != (0, 0, 0):
                    conn.execute(
                        update(admin_notifications)
                        .where(admin_notifications.c.id == notif._mapping["id"])
                        .values(
                            is_dismissed=True, dismissed_at=func.current_timestamp()
                        )
                    )
