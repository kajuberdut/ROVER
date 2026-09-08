"""src/rover/vex.py — VEX (Vulnerability Exploitability eXchange) document generator & parser module.

Supports canonical OpenVEX (v0.2.0) and CycloneDX VEX document standards.
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from rover import db
from rover.db.types import FindingStatus, VexSpecType

logger = logging.getLogger(__name__)

# Map ROVER Triage Status -> OpenVEX Status
ROVER_TO_OPENVEX_STATUS = {
    FindingStatus.FALSE_POSITIVE.value: "not_affected",
    FindingStatus.ACCEPTED_RISK.value: "not_affected",
    FindingStatus.MITIGATED.value: "not_affected",
    FindingStatus.RESOLVED.value: "fixed",
}

# Map ROVER Triage Status -> CycloneDX VEX Status
ROVER_TO_CYCLONEDX_STATUS = {
    FindingStatus.FALSE_POSITIVE.value: "not_affected",
    FindingStatus.ACCEPTED_RISK.value: "not_affected",
    FindingStatus.MITIGATED.value: "not_affected",
    FindingStatus.RESOLVED.value: "resolved",
}


def generate_openvex_document(
    release_id: str, author: str = "ROVER Security Platform"
) -> dict[str, Any]:
    """Generates a canonical OpenVEX v0.2.0 JSON document for a given release."""
    now_iso = datetime.now(timezone.utc).isoformat()
    doc_id = f"https://rover.local/api/vex/doc/{uuid.uuid4().hex}"

    vex_records = db.get_latest_vex_for_release(release_id)
    statements: list[dict[str, Any]] = []

    for rec in vex_records:
        try:
            stmt_data = json.loads(rec["statement_json"])
            if isinstance(stmt_data, dict) and "vulnerability" in stmt_data:
                statements.append(stmt_data)
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            # Catch JSON syntax errors or payload structural mismatches in stored VEX statements
            logger.warning(f"Failed to parse stored VEX statement JSON: {e}")

    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": doc_id,
        "author": author,
        "timestamp": now_iso,
        "version": 1,
        "statements": statements,
    }


def generate_cyclonedx_vex_document(release_id: str) -> dict[str, Any]:
    """Generates a CycloneDX VEX JSON document with embedded vulnerability analysis blocks."""
    now_iso = datetime.now(timezone.utc).isoformat()

    vex_records = db.get_latest_vex_for_release(release_id)
    vulnerabilities: list[dict[str, Any]] = []

    for rec in vex_records:
        try:
            stmt_data = json.loads(rec["statement_json"])
            vuln_id = stmt_data.get("vulnerability", {}).get("name", "UNKNOWN")
            status = stmt_data.get("status", "not_affected")
            justification = stmt_data.get("justification")
            impact = stmt_data.get("impact_statement", "")

            analysis: dict[str, Any] = {"state": status}
            if justification:
                analysis["justification"] = justification
            if impact:
                analysis["detail"] = impact

            vulnerabilities.append(
                {
                    "id": vuln_id,
                    "analysis": analysis,
                }
            )
        except (json.JSONDecodeError, KeyError, TypeError, AttributeError) as e:
            # Catch JSON decode failures or dictionary field lookup errors in VEX records
            logger.warning(f"Failed to parse stored VEX payload: {e}")

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now_iso,
            "tools": [{"vendor": "ROVER Platform", "name": "ROVER VEX Engine"}],
        },
        "vulnerabilities": vulnerabilities,
    }


def create_openvex_statement_payload(
    vulnerability_id: str,
    product_purl: str,
    status: str,
    justification: str,
    impact_statement: str,
) -> dict[str, Any]:
    """Constructs an individual OpenVEX statement payload dictionary."""
    openvex_status = ROVER_TO_OPENVEX_STATUS.get(status, "not_affected")
    statement: dict[str, Any] = {
        "vulnerability": {"name": vulnerability_id},
        "products": [{"@id": product_purl}],
        "status": openvex_status,
        "impact_statement": impact_statement,
    }
    if openvex_status == "not_affected" and justification:
        statement["justification"] = justification

    return statement


def create_and_save_vex_statement(
    triage_id: str,
    vulnerability_id: str,
    product_purl: str,
    status: str,
    justification: str,
    impact_statement: str,
    spec_type: str = VexSpecType.OPENVEX.value,
) -> str:
    """Constructs and saves a VEX statement into the vex_statements repository table."""
    payload = create_openvex_statement_payload(
        vulnerability_id=vulnerability_id,
        product_purl=product_purl,
        status=status,
        justification=justification,
        impact_statement=impact_statement,
    )
    json_str = json.dumps(payload)
    return db.save_vex_statement(
        triage_id=triage_id, spec_type=spec_type, statement_json=json_str
    )
