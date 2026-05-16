import uuid
from typing import Any

from sqlalchemy import insert, select, update
from sqlalchemy.sql import func

from rover.db.connection import get_db_connection
from rover.db.schema import scan_jobs, semgrep_jobs


def create_job(
    target_url: str, git_ref: str | None = None, target_type: str = "repo"
) -> str:
    job_id = str(uuid.uuid4())
    with get_db_connection() as conn:
        conn.execute(
            insert(scan_jobs).values(
                id=job_id,
                target_url=target_url,
                git_ref=git_ref,
                status="queued",
                target_type=target_type,
            )
        )
    return job_id


def get_job(job_id: str) -> dict[str, Any] | None:
    with get_db_connection() as conn:
        row = conn.execute(select(scan_jobs).where(scan_jobs.c.id == job_id)).fetchone()
        return dict(row._mapping) if row else None


def update_job_status(
    job_id: str,
    status: str,
    results_json: str | None = None,
    error_message: str | None = None,
    resolved_commit: str | None = None,
    resolved_tags: str | None = None,
) -> None:
    with get_db_connection() as conn:
        conn.execute(
            update(scan_jobs)
            .where(scan_jobs.c.id == job_id)
            .values(
                status=status,
                results_json=results_json,
                error_message=error_message,
                resolved_commit=resolved_commit,
                resolved_tags=resolved_tags,
                updated_at=func.current_timestamp(),
            )
        )


def get_all_jobs() -> list[dict[str, Any]]:
    with get_db_connection() as conn:
        rows = conn.execute(
            select(scan_jobs).order_by(scan_jobs.c.created_at.desc())
        ).fetchall()
        return [dict(row._mapping) for row in rows]


def create_semgrep_job(target_url: str, git_ref: str | None = None) -> str:
    job_id = str(uuid.uuid4())
    with get_db_connection() as conn:
        conn.execute(
            insert(semgrep_jobs).values(
                id=job_id, target_url=target_url, git_ref=git_ref, status="queued"
            )
        )
    return job_id


def get_semgrep_job(job_id: str) -> dict[str, Any] | None:
    with get_db_connection() as conn:
        row = conn.execute(
            select(semgrep_jobs).where(semgrep_jobs.c.id == job_id)
        ).fetchone()
        return dict(row._mapping) if row else None


def get_semgrep_job_for_target(
    target_url: str, git_ref: str | None
) -> dict[str, Any] | None:
    with get_db_connection() as conn:
        # SQLite IFNULL equivalent in standard SQL is coalesce
        row = conn.execute(
            select(semgrep_jobs)
            .where(semgrep_jobs.c.target_url == target_url)
            .where(func.coalesce(semgrep_jobs.c.git_ref, "") == (git_ref or ""))
            .order_by(semgrep_jobs.c.created_at.desc())
            .limit(1)
        ).fetchone()
        return dict(row._mapping) if row else None


def get_completed_semgrep_job_by_commit(commit_hash: str) -> dict[str, Any] | None:
    with get_db_connection() as conn:
        row = conn.execute(
            select(semgrep_jobs)
            .where(
                semgrep_jobs.c.resolved_commit == commit_hash,
                semgrep_jobs.c.status == "completed",
            )
            .order_by(semgrep_jobs.c.created_at.asc())
            .limit(1)
        ).fetchone()
        return dict(row._mapping) if row else None


def update_semgrep_job_status(
    job_id: str,
    status: str,
    results_json: str | None = None,
    error_message: str | None = None,
    resolved_commit: str | None = None,
    resolved_tags: str | None = None,
) -> None:
    with get_db_connection() as conn:
        conn.execute(
            update(semgrep_jobs)
            .where(semgrep_jobs.c.id == job_id)
            .values(
                status=status,
                results_json=results_json,
                error_message=error_message,
                resolved_commit=resolved_commit,
                resolved_tags=resolved_tags,
                updated_at=func.current_timestamp(),
            )
        )


def claim_next_semgrep_job() -> dict[str, Any] | None:
    with get_db_connection() as conn:
        row = conn.execute(
            select(semgrep_jobs.c.id, semgrep_jobs.c.target_url, semgrep_jobs.c.git_ref)
            .where(semgrep_jobs.c.status == "queued")
            .order_by(semgrep_jobs.c.created_at.asc())
            .limit(1)
        ).fetchone()
        if row:
            job_id = row.id
            conn.execute(
                update(semgrep_jobs)
                .where(semgrep_jobs.c.id == job_id)
                .values(status="running", updated_at=func.current_timestamp())
            )
            return dict(row._mapping)
    return None


def claim_next_job() -> dict[str, Any] | None:
    with get_db_connection() as conn:
        row = conn.execute(
            select(
                scan_jobs.c.id,
                scan_jobs.c.target_url,
                scan_jobs.c.git_ref,
                scan_jobs.c.target_type,
            )
            .where(scan_jobs.c.status == "queued")
            .order_by(scan_jobs.c.created_at.asc())
            .limit(1)
        ).fetchone()
        if row:
            job_id = row.id
            conn.execute(
                update(scan_jobs)
                .where(scan_jobs.c.id == job_id)
                .values(status="running", updated_at=func.current_timestamp())
            )
            return dict(row._mapping)
    return None
