import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import insert, select

from rover.db.connection import get_db_connection
from rover.db.schema import audit_logs

audit_logger = logging.getLogger("rover.audit")


def log_audit_event(
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    user_sub: str | None = None,
    user_email: str | None = None,
    changes: dict[str, Any] | None = None,
    ip_address: str | None = None,
) -> str:
    """
    Log a human decision or administrative action both into the audit_logs database table
    and as a structured JSON log line via standard logging for SIEM shipping (Option 3 Hybrid).
    """
    audit_id = str(uuid.uuid4())
    changes_dict = changes or {}
    changes_json = json.dumps(changes_dict)
    timestamp_iso = datetime.now(timezone.utc).isoformat()

    # 1. Insert into database table for in-app history/querying
    with get_db_connection() as conn:
        conn.execute(
            insert(audit_logs).values(
                id=audit_id,
                user_sub=user_sub,
                user_email=user_email,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                changes_json=changes_json,
                ip_address=ip_address,
            )
        )

    # 2. Emit structured JSON log line for external SIEM / log collection
    log_entry = {
        "event": "audit",
        "audit_id": audit_id,
        "timestamp": timestamp_iso,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "user_sub": user_sub,
        "user_email": user_email,
        "changes": changes_dict,
        "ip_address": ip_address,
    }
    audit_logger.info(json.dumps(log_entry))

    return audit_id


def get_audit_logs(
    limit: int = 100,
    offset: int = 0,
    action: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    user_sub: str | None = None,
) -> list[dict[str, Any]]:
    """Retrieve filtered audit log entries ordered by newest first."""
    stmt = select(audit_logs).order_by(audit_logs.c.created_at.desc())

    if action:
        stmt = stmt.where(audit_logs.c.action == action)
    if resource_type:
        stmt = stmt.where(audit_logs.c.resource_type == resource_type)
    if resource_id:
        stmt = stmt.where(audit_logs.c.resource_id == resource_id)
    if user_sub:
        stmt = stmt.where(audit_logs.c.user_sub == user_sub)

    stmt = stmt.limit(limit).offset(offset)

    with get_db_connection() as conn:
        rows = conn.execute(stmt).mappings().all()
        results = []
        for r in rows:
            d = dict(r)
            if isinstance(d.get("created_at"), datetime):
                d["created_at"] = d["created_at"].isoformat()
            results.append(d)
        return results
