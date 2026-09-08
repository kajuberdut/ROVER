"""src/rover/db/vex.py — Database operations for generated VEX (OpenVEX and CycloneDX VEX) statements."""

import logging
import uuid
from typing import Any

from sqlalchemy import select

from rover.db.connection import get_db_connection
from rover.db.schema import (
    asset_vulnerabilities,
    release_assets,
    vex_statements,
    vulnerability_triage,
)

logger = logging.getLogger(__name__)


def save_vex_statement(triage_id: str, spec_type: str, statement_json: str) -> str:
    """Stores a generated OpenVEX or CycloneDX VEX statement payload."""
    vex_id = uuid.uuid4().hex
    with get_db_connection() as conn:
        conn.execute(
            vex_statements.insert().values(
                id=vex_id,
                triage_id=triage_id,
                spec_type=spec_type,
                statement_json=statement_json,
            )
        )
    return vex_id


def get_vex_statement_by_triage(triage_id: str) -> dict[str, Any] | None:
    """Fetches the VEX statement associated with a specific triage decision."""
    with get_db_connection() as conn:
        stmt = (
            select(vex_statements)
            .where(vex_statements.c.triage_id == triage_id)
            .order_by(vex_statements.c.generated_at.desc())
            .limit(1)
        )
        row = conn.execute(stmt).fetchone()
        if not row:
            return None
        return dict(row._mapping)


def get_latest_vex_for_release(release_id: str) -> list[dict[str, Any]]:
    """Retrieves all active VEX statements for assets belonging to a release."""
    with get_db_connection() as conn:
        stmt = (
            select(vex_statements)
            .join(
                vulnerability_triage,
                vex_statements.c.triage_id == vulnerability_triage.c.id,
            )
            .join(
                asset_vulnerabilities,
                vulnerability_triage.c.vulnerability_ledger_id
                == asset_vulnerabilities.c.id,
            )
            .join(
                release_assets,
                asset_vulnerabilities.c.release_asset_id == release_assets.c.id,
            )
            .where(release_assets.c.release_id == release_id)
            .order_by(vex_statements.c.generated_at.desc())
        )
        rows = conn.execute(stmt).fetchall()
        return [dict(r._mapping) for r in rows]
