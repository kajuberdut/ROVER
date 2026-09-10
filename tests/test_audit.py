"""tests/test_audit.py: Unit tests for central audit logging system (DB table + structured console logger)."""

import json
import logging

import pytest
from falcon import testing
from sqlalchemy import create_engine

from rover.db import connection, schema
from rover.db.audit import get_audit_logs, log_audit_event
from rover.routes import create_app


@pytest.fixture(autouse=True)
def sqlite_test_db() -> None:
    test_engine = create_engine("sqlite:///:memory:")
    connection.engine = test_engine
    schema.metadata.create_all(test_engine)


def test_log_audit_event_db_and_logger(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="rover.audit")

    audit_id = log_audit_event(
        action="image.link_repo",
        resource_type="image",
        resource_id="img_123",
        user_sub="usr_admin",
        user_email="admin@rover.local",
        changes={"old_ref": "1.16.0", "new_ref": "release-1.16.0"},
        ip_address="127.0.0.1",
    )

    assert audit_id is not None

    # 1. Verify record stored in database
    logs = get_audit_logs(resource_type="image", resource_id="img_123")
    assert len(logs) == 1
    record = logs[0]
    assert record["id"] == audit_id
    assert record["action"] == "image.link_repo"
    assert record["user_sub"] == "usr_admin"
    assert record["user_email"] == "admin@rover.local"
    parsed_changes = json.loads(record["changes_json"])
    assert parsed_changes["new_ref"] == "release-1.16.0"

    # 2. Verify structured JSON log emitted to logger
    matching_records = [r for r in caplog.records if r.name == "rover.audit"]
    assert len(matching_records) == 1
    log_json = json.loads(matching_records[0].message)
    assert log_json["event"] == "audit"
    assert log_json["action"] == "image.link_repo"
    assert log_json["changes"]["new_ref"] == "release-1.16.0"


def test_get_audit_logs_filtering() -> None:
    log_audit_event("user.promote", "user", "usr_1", user_sub="admin_1")
    log_audit_event("vulnerability.triage", "vulnerability", "vuln_1", user_sub="usr_2")
    log_audit_event("image.link_repo", "image", "img_1", user_sub="admin_1")

    # Filter by action
    user_promotes = get_audit_logs(action="user.promote")
    assert len(user_promotes) == 1
    assert user_promotes[0]["resource_id"] == "usr_1"

    # Filter by user_sub
    admin_logs = get_audit_logs(user_sub="admin_1")
    assert len(admin_logs) == 2

    # Filter by resource_type
    vuln_logs = get_audit_logs(resource_type="vulnerability")
    assert len(vuln_logs) == 1
    assert vuln_logs[0]["resource_id"] == "vuln_1"


def get_auth_headers(role: str = "system_admin") -> dict[str, str]:
    from rover.auth import COOKIE_NAME, cookie_serializer

    session_data = {
        "sub": "admin-sub",
        "email": "admin@rover.local",
        "name": "Test Admin",
        "role": role,
        "product_ids": [],
    }
    cookie_val = cookie_serializer.dumps(session_data)
    return {"Cookie": f"{COOKIE_NAME}={cookie_val}"}


def test_admin_audit_logs_api_endpoint() -> None:
    log_audit_event("release.delete", "release", "rel_999", user_sub="admin-sub")

    app = create_app()
    client = testing.TestClient(app)

    response = client.simulate_get(
        "/api/admin/audit_logs", headers=get_auth_headers("system_admin")
    )
    assert response.status_code == 200
    data = response.json
    assert data["count"] >= 1
    actions = [log["action"] for log in data["audit_logs"]]
    assert "release.delete" in actions


def test_user_management_audit_events() -> None:
    log_audit_event(
        "user.login",
        "user",
        "usr_100",
        user_sub="usr_100",
        user_email="user100@rover.local",
    )
    log_audit_event(
        "user.role_update",
        "user",
        "usr_100",
        user_sub="admin_sub",
        changes={"new_role": "system_admin"},
    )
    log_audit_event(
        "user.password_change",
        "user",
        "usr_100",
        user_email="user100@rover.local",
    )

    user_logs = get_audit_logs(resource_id="usr_100")
    assert len(user_logs) == 3
    action_types = {l["action"] for l in user_logs}
    assert action_types == {"user.login", "user.role_update", "user.password_change"}


def test_config_schedule_and_notification_audit_events() -> None:
    log_audit_event("config.update", "config", "rover.toml", user_sub="admin-sub")
    log_audit_event(
        "schedule.create",
        "scheduled_scan",
        "sched_1",
        user_sub="admin-sub",
        changes={"cron": "0 2 * * *"},
    )
    log_audit_event(
        "notification_destination.create",
        "notification_destination",
        "dest_1",
        user_sub="admin-sub",
    )
    log_audit_event(
        "notification_rule.create", "notification_rule", "rule_1", user_sub="admin-sub"
    )

    config_logs = get_audit_logs(resource_type="config")
    assert len(config_logs) == 1
    assert config_logs[0]["action"] == "config.update"

    schedule_logs = get_audit_logs(resource_type="scheduled_scan")
    assert len(schedule_logs) == 1

    dest_logs = get_audit_logs(resource_type="notification_destination")
    assert len(dest_logs) == 1

    rule_logs = get_audit_logs(resource_type="notification_rule")
    assert len(rule_logs) == 1
