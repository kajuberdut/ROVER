"""rover/scheduler.py: Background scheduler engine for executing scheduled scans with auditing & logging."""

import logging
from datetime import datetime, timezone

from rover import db

logger = logging.getLogger("rover.scheduler")


def dispatch_due_scheduled_scans() -> int:
    """Checks for due scheduled scans, dispatches scanner jobs for active releases, and logs execution audits."""
    due_schedules = db.get_due_scheduled_scans()
    if not due_schedules:
        return 0

    logger.info("Found %d due scheduled scan(s) to dispatch", len(due_schedules))
    dispatched_count = 0

    for schedule in due_schedules:
        schedule_id = schedule["id"]
        schedule_name = schedule["name"]
        product_id = schedule["product_id"]
        cron_expr = schedule.get("cron_expression", "0 2 * * *")

        logger.info(
            "Triggering scheduled scan '%s' (ID: %s) for product %s (cron: %s)",
            schedule_name,
            schedule_id,
            product_id,
            cron_expr,
        )

        try:
            created_job_ids: list[str] = []

            # Resolve target releases (specific release or all active non-EOL releases)
            if schedule.get("release_id"):
                rel_target = db.get_release(schedule["release_id"])
                releases = (
                    [rel_target]
                    if rel_target and not rel_target.get("is_end_of_life")
                    else []
                )
            else:
                product_releases = db.get_product_releases(product_id)
                releases = [r for r in product_releases if not r.get("is_end_of_life")]

            for rel in releases:
                rel_assets = db.get_release_assets_with_latest_scans(rel["id"])
                for asset in rel_assets:
                    asset_type = asset.get("asset_type")
                    target_url = asset.get("asset_name")
                    git_ref = asset.get("git_ref")

                    if not target_url or not asset_type:
                        continue

                    if asset_type == "repo":
                        job_id = db.create_job(
                            target_url, git_ref=git_ref, target_type="repo"
                        )
                        created_job_ids.append(job_id)
                        semgrep_id = db.create_semgrep_job(target_url, git_ref=git_ref)
                        snyk_id = db.create_snyk_job(target_url, git_ref=git_ref)
                        created_job_ids.extend([semgrep_id, snyk_id])
                    elif asset_type == "image":
                        job_id = db.create_job(
                            target_url, git_ref=git_ref, target_type="image"
                        )
                        created_job_ids.append(job_id)
                        snyk_id = db.create_snyk_job(target_url, git_ref=git_ref)
                        created_job_ids.append(snyk_id)
                        if asset.get("source_repo_url"):
                            semgrep_id = db.create_semgrep_job(
                                target_url=asset["source_repo_url"],
                                git_ref=asset.get("image_source_git_ref"),
                            )
                            created_job_ids.append(semgrep_id)
                    elif asset_type == "major_component":
                        job_id = db.create_job(
                            target_url, git_ref=git_ref, target_type="major_component"
                        )
                        created_job_ids.append(job_id)

            now_utc = datetime.now(timezone.utc)
            next_run = db.compute_next_run(cron_expr, now_utc)

            db.update_scheduled_scan(
                schedule_id=schedule_id,
                last_run_at=now_utc,
                next_run_at=next_run,
                last_status="success",
            )

            db.log_schedule_execution(
                schedule_id=schedule_id,
                status="success",
                jobs_created_count=len(created_job_ids),
                details={"enqueued_job_ids": created_job_ids},
            )

            logger.info(
                "Successfully dispatched scheduled scan '%s' (ID: %s). Enqueued %d job(s). Next run: %s",
                schedule_name,
                schedule_id,
                len(created_job_ids),
                next_run,
            )
            dispatched_count += 1

        except Exception as exc:
            logger.error(
                "Failed to dispatch scheduled scan '%s' (ID: %s): %s",
                schedule_name,
                schedule_id,
                exc,
                exc_info=True,
            )
            now_utc = datetime.now(timezone.utc)
            next_run = db.compute_next_run(cron_expr, now_utc)

            db.update_scheduled_scan(
                schedule_id=schedule_id,
                last_run_at=now_utc,
                next_run_at=next_run,
                last_status="failed",
            )
            db.log_schedule_execution(
                schedule_id=schedule_id,
                status="failed",
                jobs_created_count=0,
                error_message=str(exc),
            )

    return dispatched_count
