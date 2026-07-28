"""rover/db/schedules.py: Database functions for managing scheduled scans and execution audit logs."""

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, cast

from croniter import croniter
from sqlalchemy import func, insert, select, update

from rover.db.connection import get_db_connection
from rover.db.schema import schedule_execution_logs, scheduled_scans

logger = logging.getLogger("rover.db.schedules")


def compute_next_run(cron_expr: str, start_time: datetime | None = None) -> datetime:
    """Calculates the next run timestamp given a cron expression."""
    base = start_time or datetime.now(timezone.utc)
    if base.tzinfo is None:
        base = base.replace(tzinfo=timezone.utc)
    try:
        iter_cron = croniter(cron_expr, base)
        return cast(datetime, iter_cron.get_next(datetime))
    except Exception as exc:
        logger.warning(
            f"Invalid cron expression '{cron_expr}': {exc}. Defaulting to daily 2 AM."
        )
        iter_cron = croniter("0 2 * * *", base)
        return cast(datetime, iter_cron.get_next(datetime))


def create_scheduled_scan(
    product_id: str,
    name: str,
    cron_expression: str = "0 2 * * *",
    release_id: str | None = None,
    enabled: bool = True,
    user_sub: str | None = None,
) -> str:
    schedule_id = str(uuid.uuid4())
    next_run = compute_next_run(cron_expression)

    with get_db_connection() as conn:
        conn.execute(
            insert(scheduled_scans).values(
                id=schedule_id,
                name=name,
                product_id=product_id,
                release_id=release_id,
                cron_expression=cron_expression,
                enabled=enabled,
                next_run_at=next_run,
                created_by_user_sub=user_sub,
            )
        )
    logger.info(
        f"Created scheduled scan '{name}' (ID: {schedule_id}) for product {product_id}. Next run: {next_run}"
    )
    return schedule_id


def get_scheduled_scan(schedule_id: str) -> dict[str, Any] | None:
    with get_db_connection() as conn:
        row = conn.execute(
            select(scheduled_scans).where(scheduled_scans.c.id == schedule_id)
        ).fetchone()
        return dict(row._mapping) if row else None


def get_scheduled_scans_for_product(product_id: str) -> list[dict[str, Any]]:
    with get_db_connection() as conn:
        rows = conn.execute(
            select(scheduled_scans)
            .where(scheduled_scans.c.product_id == product_id)
            .order_by(scheduled_scans.c.created_at.desc())
        ).fetchall()
        return [dict(r._mapping) for r in rows]


def get_due_scheduled_scans() -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc)
    with get_db_connection() as conn:
        rows = conn.execute(
            select(scheduled_scans).where(
                scheduled_scans.c.enabled == True,  # noqa: E712
                (scheduled_scans.c.next_run_at.is_(None))
                | (scheduled_scans.c.next_run_at <= now),
            )
        ).fetchall()
        return [dict(r._mapping) for r in rows]


def update_scheduled_scan(
    schedule_id: str,
    name: str | None = None,
    cron_expression: str | None = None,
    release_id: str | None = None,
    enabled: bool | None = None,
    last_run_at: datetime | None = None,
    next_run_at: datetime | None = None,
    last_status: str | None = None,
) -> None:
    values: dict[str, Any] = {"updated_at": func.current_timestamp()}
    if name is not None:
        values["name"] = name
    if cron_expression is not None:
        values["cron_expression"] = cron_expression
        if next_run_at is None:
            values["next_run_at"] = compute_next_run(cron_expression)
    if release_id is not None:
        values["release_id"] = release_id
    if enabled is not None:
        values["enabled"] = enabled
    if last_run_at is not None:
        values["last_run_at"] = last_run_at
    if next_run_at is not None:
        values["next_run_at"] = next_run_at
    if last_status is not None:
        values["last_status"] = last_status

    with get_db_connection() as conn:
        conn.execute(
            update(scheduled_scans)
            .where(scheduled_scans.c.id == schedule_id)
            .values(**values)
        )
    logger.debug(f"Updated scheduled scan {schedule_id}: {values}")


def delete_scheduled_scan(schedule_id: str) -> None:
    with get_db_connection() as conn:
        conn.execute(
            scheduled_scans.delete().where(scheduled_scans.c.id == schedule_id)
        )
    logger.info(f"Deleted scheduled scan {schedule_id}")


def log_schedule_execution(
    schedule_id: str,
    status: str,
    jobs_created_count: int = 0,
    details: dict[str, Any] | list[Any] | None = None,
    error_message: str | None = None,
) -> str:
    log_id = str(uuid.uuid4())
    details_str = json.dumps(details) if details is not None else None

    with get_db_connection() as conn:
        conn.execute(
            insert(schedule_execution_logs).values(
                id=log_id,
                schedule_id=schedule_id,
                status=status,
                jobs_created_count=jobs_created_count,
                details_json=details_str,
                error_message=error_message,
            )
        )
    logger.info(
        f"Logged schedule execution for {schedule_id}: status={status}, jobs_created={jobs_created_count}"
    )
    return log_id


def get_schedule_execution_logs(
    schedule_id: str, limit: int = 20
) -> list[dict[str, Any]]:
    with get_db_connection() as conn:
        rows = conn.execute(
            select(schedule_execution_logs)
            .where(schedule_execution_logs.c.schedule_id == schedule_id)
            .order_by(schedule_execution_logs.c.triggered_at.desc())
            .limit(limit)
        ).fetchall()
        return [dict(r._mapping) for r in rows]
