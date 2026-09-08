"""tests/test_sbom_vex_triage.py — Unit tests for Phase 1 Database Layer (SBOM, Triage, VEX)."""

import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine

from rover import db
from rover.db import connection, schema
from rover.db.types import (
    FindingStatus,
    SbomComponentType,
    SbomFormat,
    VexJustification,
    VexSpecType,
    VulnerabilitySeverity,
)


@pytest.fixture(autouse=True)
def setup_test_db():
    """Sets up an in-memory SQLite database for testing."""
    test_engine = create_engine("sqlite:///:memory:")
    connection.engine = test_engine
    schema.metadata.create_all(test_engine)
    yield test_engine


def test_sboms_db_operations():
    """Tests creating and querying SBOM records and parsed components."""
    # Seed product, release, asset
    prod_id = db.add_product("Test Product", "Test Description")
    rel_id = db.add_release(prod_id, "v1.0.0", "Release v1.0.0")
    img_id = db.add_image("alpine:latest")
    asset_id = db.add_release_asset(rel_id, "image", img_id)

    raw_cdx = json.dumps(
        {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}
    )
    components = [
        {
            "name": "openssl",
            "version": "3.0.8",
            "purl": "pkg:apk/alpine/openssl@3.0.8",
            "license_spdx": "Apache-2.0",
            "component_type": SbomComponentType.LIBRARY.value,
        },
        {
            "name": "curl",
            "version": "8.0.1",
            "purl": "pkg:apk/alpine/curl@8.0.1",
            "license_spdx": "MIT",
            "component_type": SbomComponentType.APPLICATION.value,
        },
    ]

    sbom_id = db.add_sbom(
        release_asset_id=asset_id,
        format_name=SbomFormat.CYCLONEDX.value,
        spec_version="1.6",
        raw_payload=raw_cdx,
        serial_number="urn:uuid:12345",
        components=components,
    )

    assert sbom_id is not None

    sbom_record = db.get_sbom_for_asset(asset_id)
    assert sbom_record is not None
    assert sbom_record["format"] == "cyclonedx"
    assert sbom_record["spec_version"] == "1.6"

    comps = db.list_sbom_components(sbom_id=sbom_id)
    assert len(comps) == 2
    comp_names = {c["name"] for c in comps}
    assert comp_names == {"openssl", "curl"}


def test_vulnerability_ledger_and_triage():
    """Tests central vulnerability ledger, human triage decisions, and expiration."""
    prod_id = db.add_product("Prod Vuln", "Vuln Test")
    rel_id = db.add_release(prod_id, "v2.0.0", "Release 2.0")
    repo_id = db.add_repository("https://github.com/org/repo.git")
    asset_id = db.add_release_asset(rel_id, "repo", repo_id)
    user = db.upsert_user(
        "auditor-sub", "auditor@example.com", "Auditor", role="system_admin"
    )
    user_sub = user["sub"]

    # Record initial vulnerability finding
    vuln_id = db.record_vulnerability(
        release_asset_id=asset_id,
        scanner_name="trivy",
        vulnerability_id="CVE-2024-1234",
        package_name="urllib3",
        installed_version="1.26.5",
        severity=VulnerabilitySeverity.HIGH.value,
        fixed_version="1.26.12",
    )
    assert vuln_id is not None

    vulns = db.list_asset_vulnerabilities(release_asset_id=asset_id)
    assert len(vulns) == 1
    assert vulns[0]["current_status"] == FindingStatus.OPEN.value

    # Submit human triage decision (Accepted Risk)
    expires = datetime.now(timezone.utc) + timedelta(days=30)
    triage_id = db.add_triage_decision(
        vulnerability_ledger_id=vuln_id,
        user_sub=user_sub,
        status=FindingStatus.ACCEPTED_RISK.value,
        justification=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH.value,
        impact_statement="Library is installed but functions are unused.",
        expires_at=expires,
    )
    assert triage_id is not None

    # Check updated finding status
    vulns_updated = db.list_asset_vulnerabilities(release_asset_id=asset_id)
    assert vulns_updated[0]["current_status"] == FindingStatus.ACCEPTED_RISK.value

    # Check audit history
    history = db.get_vulnerability_triage_history(vuln_id)
    assert len(history) == 1
    assert history[0]["status"] == "accepted_risk"

    # Revoke triage
    success = db.revoke_triage_decision(triage_id)
    assert success is True
    vulns_reverted = db.list_asset_vulnerabilities(release_asset_id=asset_id)
    assert vulns_reverted[0]["current_status"] == FindingStatus.OPEN.value


def test_triage_expiration():
    """Tests automated cleanup of expired risk acceptances."""
    prod_id = db.add_product("Prod Expire", "Expire Test")
    rel_id = db.add_release(prod_id, "v3.0.0", "Release 3.0")
    img_id = db.add_image("ubuntu:latest")
    asset_id = db.add_release_asset(rel_id, "image", img_id)
    user_admin = db.upsert_user(
        "admin-sub", "admin@example.com", "Admin", role="system_admin"
    )
    user_sub = user_admin["sub"]

    vuln_id = db.record_vulnerability(
        release_asset_id=asset_id,
        scanner_name="trivy",
        vulnerability_id="CVE-2024-9999",
        package_name="openssl",
        installed_version="1.1.1",
        severity=VulnerabilitySeverity.CRITICAL.value,
    )

    # Set triage decision with PAST expiration date
    past_date = datetime.now(timezone.utc) - timedelta(days=1)
    db.add_triage_decision(
        vulnerability_ledger_id=vuln_id,
        user_sub=user_sub,
        status=FindingStatus.ACCEPTED_RISK.value,
        justification=VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST.value,
        impact_statement="Temporary bypass",
        expires_at=past_date,
    )

    # Run expiration worker
    expired_count = db.expire_outdated_triage_decisions()
    assert expired_count == 1

    vulns = db.list_asset_vulnerabilities(release_asset_id=asset_id)
    assert vulns[0]["current_status"] == FindingStatus.OPEN.value


def test_vex_statements():
    """Tests saving and retrieving VEX statement records."""
    prod_id = db.add_product("Prod VEX", "VEX Test")
    rel_id = db.add_release(prod_id, "v4.0.0", "Release 4.0")
    img_id = db.add_image("python:3.11-slim")
    asset_id = db.add_release_asset(rel_id, "image", img_id)
    user_vex = db.upsert_user(
        "vexuser-sub", "vexuser@example.com", "VEX User", role="system_admin"
    )
    user_sub = user_vex["sub"]

    vuln_id = db.record_vulnerability(
        release_asset_id=asset_id,
        scanner_name="semgrep",
        vulnerability_id="RULE-SAST-001",
        package_name="src/app.py",
        installed_version="n/a",
        severity=VulnerabilitySeverity.MEDIUM.value,
    )

    triage_id = db.add_triage_decision(
        vulnerability_ledger_id=vuln_id,
        user_sub=user_sub,
        status=FindingStatus.FALSE_POSITIVE.value,
        justification=VexJustification.VULNERABLE_CODE_NOT_PRESENT.value,
        impact_statement="Sanitization is handled upstream.",
    )

    openvex_json = json.dumps(
        {"@context": "https://openvex.dev/ns/v0.2.0", "statements": []}
    )
    vex_id = db.save_vex_statement(
        triage_id=triage_id,
        spec_type=VexSpecType.OPENVEX.value,
        statement_json=openvex_json,
    )
    assert vex_id is not None

    vex_record = db.get_vex_statement_by_triage(triage_id)
    assert vex_record is not None
    assert vex_record["spec_type"] == "openvex"

    release_vex = db.get_latest_vex_for_release(rel_id)
    assert len(release_vex) == 1


def test_parse_postgres_interval_and_approval_override():
    """Tests interval string parsing and expiration override during proposal approval."""
    from rover.db.triage import parse_postgres_interval

    now = datetime.now(timezone.utc)
    dt_30d = parse_postgres_interval("30 days", base_time=now)
    assert dt_30d is not None
    assert (dt_30d - now).days == 30

    dt_6m = parse_postgres_interval("6 months", base_time=now)
    assert dt_6m is not None
    assert (dt_6m - now).days == 180

    dt_none = parse_postgres_interval("indefinite")
    assert dt_none is None

    # Test approving a proposal with overridden expiration interval
    prod_id = db.add_product("Prod Override Exp", "Override Test")
    rel_id = db.add_release(prod_id, "v5.0.0", "Release 5.0")
    img_id = db.add_image("nginx:latest")
    asset_id = db.add_release_asset(rel_id, "image", img_id)
    user_eng = db.upsert_user("eng-sub", "eng@example.com", "Engineer", role="viewer")
    user_adm = db.upsert_user(
        "admin-sub", "admin@example.com", "Admin", role="system_admin"
    )

    vuln_id = db.record_vulnerability(
        release_asset_id=asset_id,
        scanner_name="trivy",
        vulnerability_id="CVE-2024-8888",
        package_name="nginx",
        installed_version="1.24.0",
        severity=VulnerabilitySeverity.HIGH.value,
    )

    # Engineer submits proposal requesting 90 days
    triage_id = db.add_triage_decision(
        vulnerability_ledger_id=vuln_id,
        user_sub=user_eng["sub"],
        status=FindingStatus.MITIGATED.value,
        justification=VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST.value,
        impact_statement="Mitigated by WAF rules",
        expires_at="90 days",
        is_approved=False,
    )

    triage_rec = db.get_triage_decision(triage_id)
    assert triage_rec is not None
    assert triage_rec["triage_state"] == "pending_approval"

    # Admin approves but overrides expiration to 30 days
    ok = db.approve_triage_decision(triage_id, user_adm["sub"], expires_at="30 days")
    assert ok is True

    approved_rec = db.get_triage_decision(triage_id)
    assert approved_rec is not None
    assert approved_rec["triage_state"] == "active"
    assert approved_rec["expires_at"] is not None
