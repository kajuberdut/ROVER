"""src/rover/db/sboms.py — Database operations for Software Bill of Materials (SBOMs)."""

import logging
import uuid
from typing import Any

from sqlalchemy import select

from rover.db.connection import get_db_connection
from rover.db.schema import sbom_components, sboms

logger = logging.getLogger(__name__)


def add_sbom(
    release_asset_id: str,
    format_name: str,
    spec_version: str,
    raw_payload: str,
    serial_number: str | None = None,
    components: list[dict[str, Any]] | None = None,
) -> str:
    """Inserts a raw SBOM payload and optional parsed component nodes into PostgreSQL."""
    sbom_id = uuid.uuid4().hex
    with get_db_connection() as conn:
        conn.execute(
            sboms.insert().values(
                id=sbom_id,
                release_asset_id=release_asset_id,
                format=format_name,
                spec_version=spec_version,
                serial_number=serial_number,
                raw_payload=raw_payload,
            )
        )

        if components:
            comp_rows = [
                {
                    "id": uuid.uuid4().hex,
                    "sbom_id": sbom_id,
                    "name": comp.get("name", "unknown"),
                    "version": comp.get("version", "unknown"),
                    "purl": comp.get("purl"),
                    "cpe": comp.get("cpe"),
                    "license_spdx": comp.get("license_spdx"),
                    "component_type": comp.get("component_type", "library"),
                }
                for comp in components
            ]
            conn.execute(sbom_components.insert(), comp_rows)

    return sbom_id


def get_sbom_for_asset(release_asset_id: str) -> dict[str, Any] | None:
    """Fetches the latest SBOM document record for a given release asset."""
    with get_db_connection() as conn:
        stmt = (
            select(sboms)
            .where(sboms.c.release_asset_id == release_asset_id)
            .order_by(sboms.c.created_at.desc())
            .limit(1)
        )
        row = conn.execute(stmt).fetchone()
        if not row:
            return None
        return dict(row._mapping)


def list_sbom_components(
    sbom_id: str | None = None, release_asset_id: str | None = None
) -> list[dict[str, Any]]:
    """Returns parsed SBOM components filtered by sbom_id or release_asset_id."""
    with get_db_connection() as conn:
        if sbom_id:
            stmt = select(sbom_components).where(sbom_components.c.sbom_id == sbom_id)
        elif release_asset_id:
            latest_sbom_stmt = (
                select(sboms.c.id)
                .where(sboms.c.release_asset_id == release_asset_id)
                .order_by(sboms.c.created_at.desc())
                .limit(1)
            )
            target_sbom_id = conn.scalar(latest_sbom_stmt)
            if not target_sbom_id:
                return []
            stmt = select(sbom_components).where(
                sbom_components.c.sbom_id == target_sbom_id
            )
        else:
            stmt = select(sbom_components)

        rows = conn.execute(stmt).fetchall()
        return [dict(r._mapping) for r in rows]
