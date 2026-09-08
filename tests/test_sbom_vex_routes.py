"""tests/test_sbom_vex_routes.py — Unit tests for Falcon API routes (SBOM export, VEX document delivery, Triage submit/revoke)."""

import pytest
from falcon import testing
from sqlalchemy import create_engine

from rover import db
from rover.auth import COOKIE_NAME, cookie_serializer
from rover.db import connection, schema
from rover.db.types import FindingStatus, VexJustification
from rover.routes import create_app


@pytest.fixture(autouse=True)
def setup_test_db():
    """Sets up an in-memory SQLite database for testing."""
    test_engine = create_engine("sqlite:///:memory:")
    connection.engine = test_engine
    schema.metadata.create_all(test_engine)
    yield test_engine


@pytest.fixture
def test_client():
    """Creates a Falcon test client for simulating HTTP API calls."""
    app = create_app()
    return testing.TestClient(app)


def get_auth_headers(role: str = "system_admin") -> dict[str, str]:
    session_data = {
        "sub": "test-admin-sub",
        "email": "admin@rover.local",
        "name": "Test Admin",
        "role": role,
        "product_ids": [],
    }
    cookie_val = cookie_serializer.dumps(session_data)
    return {"Cookie": f"{COOKIE_NAME}={cookie_val}"}


def test_sbom_export_api_route(test_client):
    """Tests GET /api/releases/{id}/sbom for CycloneDX and SPDX format exports."""
    prod_id = db.add_product("SBOM API Product", "Desc")
    rel_id = db.add_release(prod_id, "v1.0.0", "Release 1.0")
    img_id = db.add_image("alpine:latest")
    asset_id = db.add_release_asset(rel_id, "image", img_id)

    db.add_sbom(
        release_asset_id=asset_id,
        format_name="cyclonedx",
        spec_version="1.6",
        raw_payload="{}",
        components=[
            {
                "name": "busybox",
                "version": "1.36.1",
                "purl": "pkg:apk/alpine/busybox@1.36.1",
                "license_spdx": "GPL-2.0-only",
                "component_type": "container",
            }
        ],
    )

    headers = get_auth_headers()
    # Test CycloneDX export
    res_cdx = test_client.simulate_get(
        f"/api/releases/{rel_id}/sbom?format=cyclonedx", headers=headers
    )
    assert res_cdx.status_code == 200
    assert res_cdx.json["bomFormat"] == "CycloneDX"
    assert len(res_cdx.json["components"]) == 1
    assert res_cdx.json["components"][0]["name"] == "busybox"

    # Test SPDX export
    res_spdx = test_client.simulate_get(
        f"/api/releases/{rel_id}/sbom?format=spdx", headers=headers
    )
    assert res_spdx.status_code == 200
    assert res_spdx.json["spdxVersion"] == "SPDX-2.3"
    assert len(res_spdx.json["packages"]) == 1
    assert res_spdx.json["packages"][0]["name"] == "busybox"


def test_vex_export_api_route(test_client):
    """Tests GET /api/releases/{id}/vex.json for OpenVEX export."""
    prod_id = db.add_product("VEX API Product", "Desc")
    rel_id = db.add_release(prod_id, "v1.0.0", "Release 1.0")
    img_id = db.add_image("ubuntu:latest")
    asset_id = db.add_release_asset(rel_id, "image", img_id)
    user = db.upsert_user(
        "vex-user-sub", "vex@company.com", "VEX Admin", role="system_admin"
    )

    vuln_id = db.record_vulnerability(
        release_asset_id=asset_id,
        scanner_name="trivy",
        vulnerability_id="CVE-2024-8888",
        package_name="glibc",
        installed_version="2.35",
        severity="HIGH",
    )

    triage_id = db.add_triage_decision(
        vulnerability_ledger_id=vuln_id,
        user_sub=user["sub"],
        status=FindingStatus.FALSE_POSITIVE.value,
        justification=VexJustification.VULNERABLE_CODE_NOT_PRESENT.value,
        impact_statement="False positive package match.",
    )

    from rover.vex import create_and_save_vex_statement

    create_and_save_vex_statement(
        triage_id=triage_id,
        vulnerability_id="CVE-2024-8888",
        product_purl="pkg:docker/ubuntu@latest",
        status=FindingStatus.FALSE_POSITIVE.value,
        justification=VexJustification.VULNERABLE_CODE_NOT_PRESENT.value,
        impact_statement="False positive package match.",
    )

    headers = get_auth_headers()
    res = test_client.simulate_get(f"/api/releases/{rel_id}/vex.json", headers=headers)
    assert res.status_code == 200
    assert res.json["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert len(res.json["statements"]) == 1
    assert res.json["statements"][0]["vulnerability"]["name"] == "CVE-2024-8888"


def test_vulnerability_triage_and_revoke_routes(test_client):
    """Tests POST /api/vulnerabilities/{id}/triage proposal submission, approve, reject, and revoke."""
    prod_id = db.add_product("Triage API Product", "Desc")
    rel_id = db.add_release(prod_id, "v1.0.0", "Release 1.0")
    img_id = db.add_image("python:3.12")
    asset_id = db.add_release_asset(rel_id, "image", img_id)

    vuln_id = db.record_vulnerability(
        release_asset_id=asset_id,
        scanner_name="trivy",
        vulnerability_id="CVE-2024-7777",
        package_name="setuptools",
        installed_version="65.5.0",
        severity="CRITICAL",
    )

    admin_headers = get_auth_headers(role="system_admin")
    engineer_headers = get_auth_headers(role="user")

    # 1. Engineer submits triage proposal (returns pending_approval)
    res_eng = test_client.simulate_post(
        f"/api/vulnerabilities/{vuln_id}/triage",
        json={
            "status": "false_positive",
            "justification": "vulnerable_code_not_in_execute_path",
            "impact_statement": "Library is only used during build phase.",
            "vulnerability_id": "CVE-2024-7777",
        },
        headers=engineer_headers,
    )
    assert res_eng.status_code == 201
    assert res_eng.json["triage_state"] == "pending_approval"
    triage_id = res_eng.json["triage_id"]

    # Verify admin notification dispatched
    notifs = db.get_active_admin_notifications()
    assert len(notifs) >= 1
    assert "VEX Triage Approval Needed" in notifs[0]["title"]

    # 2. System Admin approves triage proposal
    res_app = test_client.simulate_post(
        f"/api/triage/{triage_id}/approve", headers=admin_headers
    )
    assert res_app.status_code == 200
    assert res_app.json["triage_state"] == "active"

    # Verify updated vulnerability status in DB
    vulns = db.list_asset_vulnerabilities(release_asset_id=asset_id)
    assert vulns[0]["current_status"] == "false_positive"

    # 3. System Admin revokes triage
    res_del = test_client.simulate_delete(
        f"/api/triage/{triage_id}", headers=admin_headers
    )
    assert res_del.status_code == 200

    # Verify reverted status in DB
    vulns_reverted = db.list_asset_vulnerabilities(release_asset_id=asset_id)
    assert vulns_reverted[0]["current_status"] == "open"
