"""tests/test_vex_engine.py — Unit tests for Phase 3 VEX Engine (OpenVEX & CycloneDX VEX generation)."""

import pytest
from sqlalchemy import create_engine

from rover import db
from rover.db import connection, schema
from rover.db.types import FindingStatus, VexJustification, VexSpecType
from rover.vex import (
    create_and_save_vex_statement,
    create_openvex_statement_payload,
    generate_cyclonedx_vex_document,
    generate_openvex_document,
)


@pytest.fixture(autouse=True)
def setup_test_db():
    """Sets up an in-memory SQLite database for testing."""
    test_engine = create_engine("sqlite:///:memory:")
    connection.engine = test_engine
    schema.metadata.create_all(test_engine)
    yield test_engine


def test_create_openvex_statement_payload():
    """Tests constructing individual OpenVEX statement payload dicts."""
    payload = create_openvex_statement_payload(
        vulnerability_id="CVE-2024-21626",
        product_purl="pkg:docker/my-org/core-service@v1.4.0",
        status=FindingStatus.ACCEPTED_RISK.value,
        justification=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH.value,
        impact_statement="Container operates in unprivileged mode.",
    )

    assert payload["vulnerability"]["name"] == "CVE-2024-21626"
    assert payload["status"] == "not_affected"
    assert payload["justification"] == "vulnerable_code_not_in_execute_path"
    assert payload["products"][0]["@id"] == "pkg:docker/my-org/core-service@v1.4.0"


def test_generate_openvex_and_cyclonedx_vex_documents():
    """Tests generating complete OpenVEX and CycloneDX VEX JSON documents for a release."""
    prod_id = db.add_product("VEX Prod", "VEX Description")
    rel_id = db.add_release(prod_id, "v1.0.0", "Release 1.0")
    img_id = db.add_image("my-service:v1.0.0")
    asset_id = db.add_release_asset(rel_id, "image", img_id)
    user = db.upsert_user(
        "vex-admin", "admin@company.com", "Admin", role="system_admin"
    )

    vuln_id = db.record_vulnerability(
        release_asset_id=asset_id,
        scanner_name="trivy",
        vulnerability_id="CVE-2024-1111",
        package_name="openssl",
        installed_version="1.1.1",
        severity="CRITICAL",
    )

    triage_id = db.add_triage_decision(
        vulnerability_ledger_id=vuln_id,
        user_sub=user["sub"],
        status=FindingStatus.FALSE_POSITIVE.value,
        justification=VexJustification.VULNERABLE_CODE_NOT_PRESENT.value,
        impact_statement="Package signature misidentified.",
    )

    vex_id = create_and_save_vex_statement(
        triage_id=triage_id,
        vulnerability_id="CVE-2024-1111",
        product_purl="pkg:docker/my-service@v1.0.0",
        status=FindingStatus.FALSE_POSITIVE.value,
        justification=VexJustification.VULNERABLE_CODE_NOT_PRESENT.value,
        impact_statement="Package signature misidentified.",
        spec_type=VexSpecType.OPENVEX.value,
    )
    assert vex_id is not None

    # Test OpenVEX document generation
    openvex_doc = generate_openvex_document(rel_id)
    assert openvex_doc["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert openvex_doc["version"] == 1
    assert len(openvex_doc["statements"]) == 1
    assert openvex_doc["statements"][0]["vulnerability"]["name"] == "CVE-2024-1111"

    # Test CycloneDX VEX document generation
    cdx_vex_doc = generate_cyclonedx_vex_document(rel_id)
    assert cdx_vex_doc["bomFormat"] == "CycloneDX"
    assert len(cdx_vex_doc["vulnerabilities"]) == 1
    assert cdx_vex_doc["vulnerabilities"][0]["id"] == "CVE-2024-1111"
    assert cdx_vex_doc["vulnerabilities"][0]["analysis"]["state"] == "not_affected"
