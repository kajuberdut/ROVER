import uuid
from typing import Any

from sqlalchemy import insert, select, update
from sqlalchemy.sql import func

from rover.db.connection import get_db_connection
from rover.db.schema import scanner_jobs


def create_scanner_job(
    scanner_name: str,
    target_url: str,
    git_ref: str | None = None,
    asset_id: str | None = None,
    target_type: str = "repo",
    product_id: str | None = None,
    credential_id: str | None = None,
) -> str:
    job_id = str(uuid.uuid4())
    with get_db_connection() as conn:
        conn.execute(
            insert(scanner_jobs).values(
                id=job_id,
                scanner_name=scanner_name,
                asset_id=asset_id,
                target_url=target_url,
                target_type=target_type,
                git_ref=git_ref,
                product_id=product_id,
                credential_id=credential_id,
                status="queued",
            )
        )
    return job_id


def get_scanner_job(job_id: str) -> dict[str, Any] | None:
    with get_db_connection() as conn:
        row = conn.execute(
            select(scanner_jobs).where(scanner_jobs.c.id == job_id)
        ).fetchone()
        return dict(row._mapping) if row else None


def update_scanner_job_status(
    job_id: str,
    status: str,
    results_json: str | None = None,
    error_message: str | None = None,
    resolved_commit: str | None = None,
    resolved_tags: str | None = None,
) -> None:
    with get_db_connection() as conn:
        row = conn.execute(
            select(scanner_jobs).where(scanner_jobs.c.id == job_id)
        ).fetchone()
        duration = None
        if row and row._mapping.get("started_at"):
            import datetime

            started = row._mapping["started_at"]
            if isinstance(started, datetime.datetime):
                now = datetime.datetime.now(datetime.timezone.utc)
                if started.tzinfo is None:
                    now = datetime.datetime.now()
                duration = max(0, int((now - started).total_seconds()))

        conn.execute(
            update(scanner_jobs)
            .where(scanner_jobs.c.id == job_id)
            .values(
                status=status,
                results_json=results_json,
                error_message=error_message,
                resolved_commit=resolved_commit,
                resolved_tags=resolved_tags,
                finished_at=func.current_timestamp()
                if status in ("completed", "failed")
                else None,
                duration_seconds=duration
                if status in ("completed", "failed")
                else None,
                updated_at=func.current_timestamp(),
            )
        )


def claim_next_scanner_job(scanner_name: str | None = None) -> dict[str, Any] | None:
    with get_db_connection() as conn:
        query = select(scanner_jobs).where(scanner_jobs.c.status == "queued")
        if scanner_name:
            query = query.where(scanner_jobs.c.scanner_name == scanner_name)
        row = conn.execute(
            query.order_by(scanner_jobs.c.created_at.asc()).limit(1)
        ).fetchone()
        if row:
            job_id = row.id
            conn.execute(
                update(scanner_jobs)
                .where(scanner_jobs.c.id == job_id)
                .values(
                    status="running",
                    started_at=func.current_timestamp(),
                    updated_at=func.current_timestamp(),
                )
            )
            return dict(row._mapping)
    return None


def get_average_scan_duration(
    scanner_name: str, target_url: str | None = None
) -> float | None:
    with get_db_connection() as conn:
        query = select(func.avg(scanner_jobs.c.duration_seconds)).where(
            scanner_jobs.c.scanner_name == scanner_name,
            scanner_jobs.c.status == "completed",
            scanner_jobs.c.duration_seconds.isnot(None),
        )
        if target_url:
            query = query.where(scanner_jobs.c.target_url == target_url)
        row = conn.execute(query).fetchone()
        if row and row[0] is not None:
            return float(row[0])
        if target_url:
            fallback = conn.execute(
                select(func.avg(scanner_jobs.c.duration_seconds)).where(
                    scanner_jobs.c.scanner_name == scanner_name,
                    scanner_jobs.c.status == "completed",
                    scanner_jobs.c.duration_seconds.isnot(None),
                )
            ).fetchone()
            if fallback and fallback[0] is not None:
                return float(fallback[0])
    return None


def get_scanner_job_for_target(
    scanner_name: str, target_url: str, git_ref: str | None = None
) -> dict[str, Any] | None:
    with get_db_connection() as conn:
        row = conn.execute(
            select(scanner_jobs)
            .where(
                scanner_jobs.c.scanner_name == scanner_name,
                scanner_jobs.c.target_url == target_url,
            )
            .where(func.coalesce(scanner_jobs.c.git_ref, "") == (git_ref or ""))
            .order_by(scanner_jobs.c.created_at.desc())
            .limit(1)
        ).fetchone()
        return dict(row._mapping) if row else None


def get_completed_scanner_job_by_commit(
    scanner_name: str, commit_hash: str
) -> dict[str, Any] | None:
    with get_db_connection() as conn:
        row = conn.execute(
            select(scanner_jobs)
            .where(
                scanner_jobs.c.scanner_name == scanner_name,
                scanner_jobs.c.resolved_commit == commit_hash,
                scanner_jobs.c.status == "completed",
            )
            .order_by(scanner_jobs.c.created_at.desc())
            .limit(1)
        ).fetchone()
        return dict(row._mapping) if row else None


def create_job(
    target_url: str, git_ref: str | None = None, target_type: str = "repo"
) -> str:
    return create_scanner_job("trivy", target_url, git_ref, target_type=target_type)


def get_job(job_id: str) -> dict[str, Any] | None:
    return get_scanner_job(job_id)


def update_job_status(
    job_id: str,
    status: str,
    results_json: str | None = None,
    error_message: str | None = None,
    resolved_commit: str | None = None,
    resolved_tags: str | None = None,
) -> None:
    update_scanner_job_status(
        job_id, status, results_json, error_message, resolved_commit, resolved_tags
    )


def get_all_jobs() -> list[dict[str, Any]]:
    with get_db_connection() as conn:
        rows = conn.execute(
            select(scanner_jobs).order_by(scanner_jobs.c.created_at.desc())
        ).fetchall()
        return [dict(row._mapping) for row in rows]


def create_semgrep_job(target_url: str, git_ref: str | None = None) -> str:
    return create_scanner_job("semgrep", target_url, git_ref)


def get_semgrep_job(job_id: str) -> dict[str, Any] | None:
    return get_scanner_job(job_id)


def get_semgrep_job_for_target(
    target_url: str, git_ref: str | None
) -> dict[str, Any] | None:
    return get_scanner_job_for_target("semgrep", target_url, git_ref)


def get_completed_semgrep_job_by_commit(commit_hash: str) -> dict[str, Any] | None:
    return get_completed_scanner_job_by_commit("semgrep", commit_hash)


def update_semgrep_job_status(
    job_id: str,
    status: str,
    results_json: str | None = None,
    error_message: str | None = None,
    resolved_commit: str | None = None,
    resolved_tags: str | None = None,
) -> None:
    update_scanner_job_status(
        job_id, status, results_json, error_message, resolved_commit, resolved_tags
    )


def claim_next_semgrep_job() -> dict[str, Any] | None:
    return claim_next_scanner_job("semgrep")


def claim_next_job() -> dict[str, Any] | None:
    return claim_next_scanner_job("trivy")


def create_snyk_job(target_url: str, git_ref: str | None = None) -> str:
    return create_scanner_job("snyk", target_url, git_ref)


def get_snyk_job(job_id: str) -> dict[str, Any] | None:
    return get_scanner_job(job_id)


def get_snyk_job_for_target(
    target_url: str, git_ref: str | None
) -> dict[str, Any] | None:
    return get_scanner_job_for_target("snyk", target_url, git_ref)


def get_completed_snyk_job_by_commit(commit_hash: str) -> dict[str, Any] | None:
    return get_completed_scanner_job_by_commit("snyk", commit_hash)


def update_snyk_job_status(
    job_id: str,
    status: str,
    results_json: str | None = None,
    error_message: str | None = None,
    resolved_commit: str | None = None,
    resolved_tags: str | None = None,
) -> None:
    update_scanner_job_status(
        job_id, status, results_json, error_message, resolved_commit, resolved_tags
    )


def claim_next_snyk_job() -> dict[str, Any] | None:
    return claim_next_scanner_job("snyk")


def get_jobs_status_summary(job_ids: list[str]) -> dict[str, int]:
    """Returns aggregated count breakdown of scanner jobs by status for a list of job IDs."""
    if not job_ids:
        return {"total": 0, "completed": 0, "failed": 0, "running": 0, "queued": 0}
    with get_db_connection() as conn:
        rows = conn.execute(
            select(scanner_jobs.c.status, func.count())
            .where(scanner_jobs.c.id.in_(job_ids))
            .group_by(scanner_jobs.c.status)
        ).fetchall()
        counts = {r[0]: r[1] for r in rows}
        return {
            "total": len(job_ids),
            "completed": counts.get("completed", 0),
            "failed": counts.get("failed", 0),
            "running": counts.get("running", 0),
            "queued": counts.get("queued", 0),
        }
