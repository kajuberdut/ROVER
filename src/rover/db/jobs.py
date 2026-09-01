import datetime
import json
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

        parsed_results = (
            (
                json.loads(results_json)
                if isinstance(results_json, str)
                else results_json
            )
            if results_json
            else None
        )

        conn.execute(
            update(scanner_jobs)
            .where(scanner_jobs.c.id == job_id)
            .values(
                status=status,
                results_json=parsed_results,
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

        if status in ("completed", "failed"):
            try:
                from rover.notifications import dispatch_event

                event_type = (
                    "scan.completed" if status == "completed" else "scan.failed"
                )
                prod_id = row._mapping.get("product_id") if row else None
                target = (
                    row._mapping.get("target_url")
                    or row._mapping.get("asset_id")
                    or job_id
                    if row
                    else job_id
                )
                scanner_name = (
                    row._mapping.get("scanner_name") or "scanner" if row else "scanner"
                )

                dispatch_event(
                    event_type=event_type,
                    payload={
                        "job_id": job_id,
                        "scanner_name": scanner_name,
                        "target": target,
                        "status": status,
                        "error_message": error_message,
                        "title": f"Scan {status.title()}: {scanner_name} on {target}",
                        "message": f"Scanner '{scanner_name}' job {job_id} on '{target}' finished with status '{status}'.",
                    },
                    product_id=prod_id,
                )

                if status == "completed" and results_json:
                    found_vulns = extract_vulnerabilities_from_results(
                        scanner_name, results_json
                    )
                    seen = set()
                    unique_vulns = []
                    for v in found_vulns:
                        key = (v["id"], v["severity"])
                        if key not in seen:
                            seen.add(key)
                            unique_vulns.append(v)

                    for v in unique_vulns:
                        dispatch_event(
                            event_type="vulnerability.found",
                            severity=v["severity"],
                            payload={
                                "job_id": job_id,
                                "scanner_name": scanner_name,
                                "target": target,
                                "cve_id": v["id"],
                                "severity": v["severity"],
                                "title": f"Vulnerability Found [{v['severity']}]: {v['id']} ({scanner_name})",
                                "message": f"Security scanner '{scanner_name}' detected {v['severity']} vulnerability '{v['id']}' on target '{target}'.",
                            },
                            product_id=prod_id,
                        )
            except Exception as e:
                import logging

                logging.getLogger(__name__).warning(
                    f"Failed to dispatch notification for job '{job_id}': {e}"
                )


def extract_vulnerabilities_from_results(
    scanner_name: str, results_json: Any
) -> list[dict[str, Any]]:
    """Parses scan results JSON and extracts standardized vulnerability dictionaries."""
    if not results_json:
        return []
    if isinstance(results_json, (dict, list)):
        data = results_json
    else:
        try:
            data = json.loads(results_json)
        except Exception:
            return []

    vulns: list[dict[str, Any]] = []

    if scanner_name == "trivy" and isinstance(data, dict):
        for res in data.get("Results", []) or []:
            if isinstance(res, dict):
                for v in res.get("Vulnerabilities", []) or []:
                    sev = (v.get("Severity") or "LOW").upper()
                    vulns.append(
                        {
                            "id": v.get("VulnerabilityID") or "Trivy Vulnerability",
                            "severity": sev,
                            "title": v.get("Title")
                            or v.get("VulnerabilityID")
                            or "Trivy Vulnerability",
                            "package": v.get("PkgName") or "",
                        }
                    )

    elif scanner_name == "semgrep" and isinstance(data, dict):
        for r in data.get("results", []) or []:
            if isinstance(r, dict):
                r_extra = r.get("extra")
                raw_sev = (
                    str(r_extra.get("severity") or "LOW").upper()
                    if isinstance(r_extra, dict)
                    else "LOW"
                )
                sev_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
                sev = sev_map.get(raw_sev, raw_sev)
                check_id = r.get("check_id") or "Semgrep Finding"
                vulns.append(
                    {
                        "id": check_id,
                        "severity": sev,
                        "title": check_id,
                        "package": r.get("path") or "",
                    }
                )

    elif scanner_name == "snyk":
        v_list: list[Any] = []
        if isinstance(data, dict):
            v_list = data.get("vulnerabilities", []) or data.get("issues", []) or []
        elif isinstance(data, list):
            v_list = data
        if isinstance(v_list, list):
            for v in v_list:
                if isinstance(v, dict):
                    sev = (v.get("severity") or "LOW").upper()
                    vid = v.get("id") or v.get("title") or "Snyk Vulnerability"
                    vulns.append(
                        {
                            "id": vid,
                            "severity": sev,
                            "title": v.get("title") or vid,
                            "package": v.get("packageName") or v.get("pkgName") or "",
                        }
                    )

    return vulns


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
    scanner_name: str, commit_hash: str, max_age_hours: int | None = None
) -> dict[str, Any] | None:
    from rover import config

    ttl_hours = (
        max_age_hours
        if max_age_hours is not None
        else getattr(config.settings.scanner, "cache_ttl_hours", 8)
    )
    cutoff_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
        hours=ttl_hours
    )

    with get_db_connection() as conn:
        row = conn.execute(
            select(scanner_jobs)
            .where(
                scanner_jobs.c.scanner_name == scanner_name,
                scanner_jobs.c.resolved_commit == commit_hash,
                scanner_jobs.c.status == "completed",
                scanner_jobs.c.created_at >= cutoff_time,
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


def get_completed_semgrep_job_by_commit(
    commit_hash: str, max_age_hours: int | None = None
) -> dict[str, Any] | None:
    return get_completed_scanner_job_by_commit(
        "semgrep", commit_hash, max_age_hours=max_age_hours
    )


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


def get_completed_snyk_job_by_commit(
    commit_hash: str, max_age_hours: int | None = None
) -> dict[str, Any] | None:
    return get_completed_scanner_job_by_commit(
        "snyk", commit_hash, max_age_hours=max_age_hours
    )


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
