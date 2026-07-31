"""src/rover/db/notification_logs.py — Database operations for notification audit logging."""

import json
import uuid
from typing import Any

from sqlalchemy import select

from rover.db.connection import get_db_connection
from rover.db.schema import notification_logs


def log_notification_attempt(
    destination_id: str,
    event_type: str,
    status: str,
    rule_id: str | None = None,
    http_status_code: int | None = None,
    error_message: str | None = None,
    payload_dict: dict[str, Any] | None = None,
    retry_count: int = 0,
) -> str:
    """Logs a notification delivery attempt to notification_logs."""
    log_id = str(uuid.uuid4())
    payload_json = json.dumps(payload_dict) if payload_dict else None

    with get_db_connection() as conn:
        conn.execute(
            notification_logs.insert().values(
                id=log_id,
                rule_id=rule_id,
                destination_id=destination_id,
                event_type=event_type,
                status=status,
                http_status_code=http_status_code,
                error_message=error_message,
                payload_json=payload_json,
                retry_count=retry_count,
            )
        )
    return log_id


def get_notification_logs(
    destination_id: str | None = None,
    rule_id: str | None = None,
    status: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Returns notification delivery attempt audit logs ordered by created_at DESC."""
    with get_db_connection() as conn:
        stmt = select(notification_logs)
        if destination_id:
            stmt = stmt.where(notification_logs.c.destination_id == destination_id)
        if rule_id:
            stmt = stmt.where(notification_logs.c.rule_id == rule_id)
        if status:
            stmt = stmt.where(notification_logs.c.status == status)

        stmt = stmt.order_by(notification_logs.c.created_at.desc()).limit(limit)
        rows = conn.execute(stmt).fetchall()

        results = []
        for r in rows:
            d = dict(r._mapping)
            if isinstance(d.get("payload_json"), str):
                try:
                    d["payload"] = json.loads(d["payload_json"])
                except Exception:
                    d["payload"] = {}
            else:
                d["payload"] = {}
            results.append(d)
        return results
