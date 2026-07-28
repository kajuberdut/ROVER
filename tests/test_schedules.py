"""tests/test_schedules.py: Unit tests for scheduled scans, cron computation, database audit logging, and routes."""

from datetime import datetime, timezone

from rover import db
from rover.scheduler import dispatch_due_scheduled_scans


def test_cron_computation():
    now = datetime(2026, 7, 27, 12, 0, 0, tzinfo=timezone.utc)
    # Daily at 2:00 AM cron expression
    next_run = db.compute_next_run("0 2 * * *", now)
    assert next_run.hour == 2
    assert next_run.minute == 0
    assert next_run.day == 28


def test_scheduled_scan_crud_and_logging():
    product_id = db.add_product("Schedule Test Product")

    # Create schedule
    sched_id = db.create_scheduled_scan(
        product_id=product_id,
        name="Nightly Audit",
        cron_expression="0 2 * * *",
    )
    assert sched_id is not None

    # Get schedule
    sched = db.get_scheduled_scan(sched_id)
    assert sched is not None
    assert sched["name"] == "Nightly Audit"
    assert sched["enabled"] is True

    # List schedules for product
    scheds = db.get_scheduled_scans_for_product(product_id)
    assert len(scheds) >= 1

    # Audit execution logging
    log_id = db.log_schedule_execution(
        schedule_id=sched_id,
        status="success",
        jobs_created_count=3,
        details={"job_ids": ["j1", "j2", "j3"]},
    )
    assert log_id is not None

    logs = db.get_schedule_execution_logs(sched_id)
    assert len(logs) == 1
    assert logs[0]["status"] == "success"
    assert logs[0]["jobs_created_count"] == 3

    # Delete schedule
    db.delete_scheduled_scan(sched_id)
    assert db.get_scheduled_scan(sched_id) is None


def test_scheduler_dispatch_engine():
    product_id = db.add_product("Scheduler Dispatch Product")
    rel_id = db.add_release(product_id, "v1.0", "Release 1.0")
    repo_id = db.add_repository("https://github.com/example/scheduler-test.git")
    db.add_release_asset(rel_id, "repo", repo_id)

    # Create a schedule whose next_run_at is in the past
    sched_id = db.create_scheduled_scan(
        product_id=product_id,
        name="Immediate Test Scan",
        cron_expression="0 2 * * *",
    )
    past_time = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    db.update_scheduled_scan(sched_id, next_run_at=past_time)

    # Dispatch due schedules
    dispatched = dispatch_due_scheduled_scans()
    assert dispatched >= 1

    # Verify schedule was updated with last_status='success' and next_run_at in the future
    updated_sched = db.get_scheduled_scan(sched_id)
    assert updated_sched["last_status"] == "success"

    next_run = updated_sched["next_run_at"]
    if isinstance(next_run, str):
        next_run = datetime.fromisoformat(next_run.replace(" ", "T"))
    if next_run.tzinfo is None:
        next_run = next_run.replace(tzinfo=timezone.utc)

    assert next_run > past_time

    # Verify execution audit log was written
    logs = db.get_schedule_execution_logs(sched_id)
    assert len(logs) >= 1
    assert logs[0]["status"] == "success"
    assert logs[0]["jobs_created_count"] > 0
