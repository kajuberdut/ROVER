"""src/rover/db/triage.py — Database operations for centralized vulnerability findings and human triage decisions."""

import logging
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select, update

from rover.db.connection import get_db_connection
from rover.db.schema import (
    asset_vulnerabilities,
    release_assets,
    releases,
    vulnerability_triage,
)
from rover.db.types import FindingStatus, TriageState

logger = logging.getLogger(__name__)


def parse_postgres_interval(
    interval_str: str | datetime | None, base_time: datetime | None = None
) -> datetime | None:
    """Parses a PostgreSQL interval string (e.g. '30 days', '90 days', '6 months') or ISO timestamp into a datetime object."""
    if not interval_str:
        return None

    if isinstance(interval_str, datetime):
        return (
            interval_str
            if interval_str.tzinfo is not None
            else interval_str.replace(tzinfo=timezone.utc)
        )

    s = interval_str.strip().lower()
    if s in ("", "none", "never", "indefinite", "null"):
        return None

    try:
        dt = datetime.fromisoformat(interval_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        pass

    now = base_time or datetime.now(timezone.utc)
    m = re.match(r"^(\d+)\s*([a-z]+)$", s)
    if not m:
        return None

    num = int(m.group(1))
    unit = m.group(2)

    if unit in ("day", "days", "d"):
        return now + timedelta(days=num)
    elif unit in ("week", "weeks", "w"):
        return now + timedelta(weeks=num)
    elif unit in ("month", "months", "m"):
        return now + timedelta(days=num * 30)
    elif unit in ("year", "years", "y"):
        return now + timedelta(days=num * 365)
    elif unit in ("hour", "hours", "h"):
        return now + timedelta(hours=num)

    return None


def ensure_default_release_asset() -> str:
    """Ensures a fallback Release Asset exists for ad-hoc / standalone vulnerability triage."""
    from rover.db.assets import add_repository
    from rover.db.products import add_product, add_release, add_release_asset
    from rover.db.schema import products, release_assets, releases

    with get_db_connection() as conn:
        row = conn.execute(
            select(release_assets.c.id)
            .join(releases, release_assets.c.release_id == releases.c.id)
            .join(products, releases.c.product_id == products.c.id)
            .where(products.c.name == "Global Asset Ledger")
        ).fetchone()
        if row:
            return str(row[0])

    prod_id = add_product(
        "Global Asset Ledger",
        "Default container for standalone ad-hoc scan findings.",
    )
    rel_id = add_release(prod_id, "1.0.0", "Global Release")
    repo_id = add_repository("https://rover.local/global-ledger")
    return add_release_asset(rel_id, "repo", repo_id)


def resolve_vulnerability_ledger_id(
    vulnerability_id: str,
    release_asset_id: str | None = None,
    package_name: str = "unknown",
    installed_version: str = "unknown",
    severity: str = "MEDIUM",
) -> str | None:
    """Resolves a CVE ID or asset_vulnerabilities primary key to its database record ID."""
    from rover.db.schema import release_assets

    with get_db_connection() as conn:
        id_stmt = select(asset_vulnerabilities.c.id).where(
            asset_vulnerabilities.c.id == vulnerability_id
        )
        existing_id = conn.scalar(id_stmt)
        if existing_id:
            return str(existing_id)

        valid_asset_id = None
        if release_asset_id:
            asset_exists = conn.scalar(
                select(release_assets.c.id).where(
                    release_assets.c.id == release_asset_id
                )
            )
            if asset_exists:
                valid_asset_id = str(release_asset_id)

        if valid_asset_id:
            cve_stmt = select(asset_vulnerabilities.c.id).where(
                asset_vulnerabilities.c.release_asset_id == valid_asset_id,
                asset_vulnerabilities.c.vulnerability_id == vulnerability_id,
            )
            if package_name and package_name != "unknown":
                cve_stmt = cve_stmt.where(
                    asset_vulnerabilities.c.package_name == package_name
                )
            found_id = conn.scalar(cve_stmt)
            if found_id:
                return str(found_id)

            return record_vulnerability(
                release_asset_id=valid_asset_id,
                scanner_name="trivy",
                vulnerability_id=vulnerability_id,
                package_name=package_name,
                installed_version=installed_version,
                severity=severity,
            )

        global_stmt = select(asset_vulnerabilities.c.id).where(
            asset_vulnerabilities.c.vulnerability_id == vulnerability_id
        )
        found_global = conn.scalar(global_stmt)
        if found_global:
            return str(found_global)

    fallback_asset_id = ensure_default_release_asset()
    return record_vulnerability(
        release_asset_id=fallback_asset_id,
        scanner_name="trivy",
        vulnerability_id=vulnerability_id,
        package_name=package_name,
        installed_version=installed_version,
        severity=severity,
    )


def record_vulnerability(
    release_asset_id: str,
    scanner_name: str,
    vulnerability_id: str,
    package_name: str,
    installed_version: str,
    severity: str,
    fixed_version: str | None = None,
) -> str:
    """Inserts or updates a finding in the centralized asset_vulnerabilities ledger."""
    with get_db_connection() as conn:
        stmt = select(asset_vulnerabilities).where(
            asset_vulnerabilities.c.release_asset_id == release_asset_id,
            asset_vulnerabilities.c.scanner_name == scanner_name,
            asset_vulnerabilities.c.vulnerability_id == vulnerability_id,
            asset_vulnerabilities.c.package_name == package_name,
        )
        existing = conn.execute(stmt).fetchone()
        now = datetime.now(timezone.utc)

        if existing:
            vuln_id = existing._mapping["id"]
            conn.execute(
                update(asset_vulnerabilities)
                .where(asset_vulnerabilities.c.id == vuln_id)
                .values(
                    installed_version=installed_version,
                    fixed_version=fixed_version or existing._mapping["fixed_version"],
                    severity=severity,
                    last_seen_at=now,
                )
            )
            return str(vuln_id)
        else:
            vuln_id = uuid.uuid4().hex
            conn.execute(
                asset_vulnerabilities.insert().values(
                    id=vuln_id,
                    release_asset_id=release_asset_id,
                    scanner_name=scanner_name,
                    vulnerability_id=vulnerability_id,
                    package_name=package_name,
                    installed_version=installed_version,
                    fixed_version=fixed_version,
                    severity=severity.upper(),
                    current_status=FindingStatus.OPEN.value,
                    first_seen_at=now,
                    last_seen_at=now,
                )
            )
            return vuln_id


def list_asset_vulnerabilities(
    release_asset_id: str | None = None, status: str | None = None
) -> list[dict[str, Any]]:
    """Lists vulnerabilities from the ledger filtered by release_asset_id or status."""
    with get_db_connection() as conn:
        stmt = select(asset_vulnerabilities)
        if release_asset_id:
            stmt = stmt.where(
                asset_vulnerabilities.c.release_asset_id == release_asset_id
            )
        if status:
            stmt = stmt.where(asset_vulnerabilities.c.current_status == status)

        stmt = stmt.order_by(asset_vulnerabilities.c.first_seen_at.desc())
        rows = conn.execute(stmt).fetchall()
        return [dict(r._mapping) for r in rows]


def add_triage_decision(
    vulnerability_ledger_id: str,
    user_sub: str,
    status: str,
    justification: str,
    impact_statement: str,
    expires_at: datetime | str | None = None,
    is_approved: bool = True,
    approved_by_user_sub: str | None = None,
) -> str:
    """Records a human triage decision. If approved, updates asset_vulnerabilities current_status immediately."""
    triage_id = uuid.uuid4().hex
    parsed_expires_at = parse_postgres_interval(expires_at)
    initial_state = (
        TriageState.ACTIVE.value if is_approved else TriageState.PENDING_APPROVAL.value
    )
    approver = approved_by_user_sub if is_approved else None

    with get_db_connection() as conn:
        conn.execute(
            vulnerability_triage.insert().values(
                id=triage_id,
                vulnerability_ledger_id=vulnerability_ledger_id,
                user_sub=user_sub,
                status=status,
                justification=justification,
                impact_statement=impact_statement,
                triage_state=initial_state,
                approved_by_user_sub=approver,
                expires_at=parsed_expires_at,
            )
        )
        if is_approved:
            conn.execute(
                update(asset_vulnerabilities)
                .where(asset_vulnerabilities.c.id == vulnerability_ledger_id)
                .values(current_status=status)
            )

    return triage_id


def get_triage_decision(triage_id: str) -> dict[str, Any] | None:
    """Fetches a specific triage decision by ID along with vulnerability details."""
    with get_db_connection() as conn:
        stmt = (
            select(
                vulnerability_triage.c.id,
                vulnerability_triage.c.vulnerability_ledger_id,
                vulnerability_triage.c.user_sub,
                vulnerability_triage.c.status,
                vulnerability_triage.c.justification,
                vulnerability_triage.c.impact_statement,
                vulnerability_triage.c.triage_state,
                vulnerability_triage.c.approved_by_user_sub,
                vulnerability_triage.c.expires_at,
                vulnerability_triage.c.created_at,
                asset_vulnerabilities.c.vulnerability_id,
                asset_vulnerabilities.c.package_name,
                asset_vulnerabilities.c.installed_version,
            )
            .select_from(
                vulnerability_triage.outerjoin(
                    asset_vulnerabilities,
                    vulnerability_triage.c.vulnerability_ledger_id
                    == asset_vulnerabilities.c.id,
                )
            )
            .where(vulnerability_triage.c.id == triage_id)
        )
        row = conn.execute(stmt).fetchone()
        return dict(row._mapping) if row else None


def approve_triage_decision(
    triage_id: str,
    admin_user_sub: str,
    expires_at: datetime | str | None = None,
) -> bool:
    """Approves a pending triage decision, activating it and updating the finding status."""
    with get_db_connection() as conn:
        stmt = select(vulnerability_triage).where(
            vulnerability_triage.c.id == triage_id
        )
        triage_entry = conn.execute(stmt).fetchone()
        if not triage_entry:
            return False

        rec = triage_entry._mapping
        ledger_id = rec["vulnerability_ledger_id"]
        target_status = rec["status"]

        update_values: dict[str, Any] = {
            "triage_state": TriageState.ACTIVE.value,
            "approved_by_user_sub": admin_user_sub,
        }

        if expires_at is not None:
            update_values["expires_at"] = parse_postgres_interval(expires_at)

        conn.execute(
            update(vulnerability_triage)
            .where(vulnerability_triage.c.id == triage_id)
            .values(**update_values)
        )

        conn.execute(
            update(asset_vulnerabilities)
            .where(asset_vulnerabilities.c.id == ledger_id)
            .values(current_status=target_status)
        )
        return True


def reject_triage_decision(triage_id: str, admin_user_sub: str) -> bool:
    """Rejects a pending triage decision, keeping the finding status open."""
    with get_db_connection() as conn:
        stmt = select(vulnerability_triage).where(
            vulnerability_triage.c.id == triage_id
        )
        triage_entry = conn.execute(stmt).fetchone()
        if not triage_entry:
            return False

        conn.execute(
            update(vulnerability_triage)
            .where(vulnerability_triage.c.id == triage_id)
            .values(
                triage_state=TriageState.REJECTED.value,
                approved_by_user_sub=admin_user_sub,
            )
        )
        return True


def get_vulnerability_triage_history(
    vulnerability_ledger_id: str,
) -> list[dict[str, Any]]:
    """Fetches full triage audit history for a specific vulnerability finding."""
    with get_db_connection() as conn:
        stmt = (
            select(vulnerability_triage)
            .where(
                vulnerability_triage.c.vulnerability_ledger_id
                == vulnerability_ledger_id
            )
            .order_by(vulnerability_triage.c.created_at.desc())
        )
        rows = conn.execute(stmt).fetchall()
        return [dict(r._mapping) for r in rows]


def revoke_triage_decision(triage_id: str) -> bool:
    """Revokes a triage decision, reverting the vulnerability status to open."""
    with get_db_connection() as conn:
        stmt = select(vulnerability_triage).where(
            vulnerability_triage.c.id == triage_id
        )
        triage_entry = conn.execute(stmt).fetchone()
        if not triage_entry:
            return False

        ledger_id = triage_entry._mapping["vulnerability_ledger_id"]
        conn.execute(
            vulnerability_triage.delete().where(vulnerability_triage.c.id == triage_id)
        )

        # Check if there are previous triage decisions for this finding
        prev_stmt = (
            select(vulnerability_triage.c.status)
            .where(vulnerability_triage.c.vulnerability_ledger_id == ledger_id)
            .order_by(vulnerability_triage.c.created_at.desc())
            .limit(1)
        )
        latest_prev = conn.scalar(prev_stmt)
        new_status = latest_prev if latest_prev else FindingStatus.OPEN.value

        conn.execute(
            update(asset_vulnerabilities)
            .where(asset_vulnerabilities.c.id == ledger_id)
            .values(current_status=new_status)
        )
        return True


def expire_outdated_triage_decisions() -> int:
    """Invalidates expired risk acceptances and reverts finding statuses to open."""
    now = datetime.now(timezone.utc)
    with get_db_connection() as conn:
        expired_stmt = select(vulnerability_triage.c.vulnerability_ledger_id).where(
            vulnerability_triage.c.expires_at.is_not(None),
            vulnerability_triage.c.expires_at <= now,
            vulnerability_triage.c.status.in_(
                [
                    FindingStatus.ACCEPTED_RISK.value,
                    FindingStatus.FALSE_POSITIVE.value,
                    FindingStatus.MITIGATED.value,
                ]
            ),
        )
        ledger_ids = conn.scalars(expired_stmt).all()
        if not ledger_ids:
            return 0

        conn.execute(
            update(asset_vulnerabilities)
            .where(asset_vulnerabilities.c.id.in_(ledger_ids))
            .values(current_status=FindingStatus.OPEN.value, last_seen_at=now)
        )
        return len(ledger_ids)


def get_product_vex_history(
    vulnerability_id: str,
    release_asset_id: str | None = None,
    product_id: str | None = None,
) -> dict[str, Any] | None:
    """Finds the most recent active or approved VEX triage decision for a vulnerability within a Product."""
    with get_db_connection() as conn:
        target_product_id = product_id
        if not target_product_id and release_asset_id:
            pid_stmt = (
                select(releases.c.product_id)
                .select_from(
                    release_assets.join(
                        releases, release_assets.c.release_id == releases.c.id
                    )
                )
                .where(release_assets.c.id == release_asset_id)
            )
            target_product_id = conn.scalar(pid_stmt)

        if not target_product_id:
            return None

        stmt = (
            select(
                vulnerability_triage.c.id.label("triage_id"),
                vulnerability_triage.c.status,
                vulnerability_triage.c.justification,
                vulnerability_triage.c.impact_statement,
                vulnerability_triage.c.triage_state,
                vulnerability_triage.c.expires_at,
                vulnerability_triage.c.created_at,
                vulnerability_triage.c.user_sub,
                asset_vulnerabilities.c.vulnerability_id,
                asset_vulnerabilities.c.package_name,
                asset_vulnerabilities.c.installed_version,
                releases.c.product_id,
            )
            .select_from(
                vulnerability_triage.join(
                    asset_vulnerabilities,
                    vulnerability_triage.c.vulnerability_ledger_id
                    == asset_vulnerabilities.c.id,
                )
                .join(
                    release_assets,
                    asset_vulnerabilities.c.release_asset_id == release_assets.c.id,
                )
                .join(releases, release_assets.c.release_id == releases.c.id)
            )
            .where(
                asset_vulnerabilities.c.vulnerability_id == vulnerability_id,
                releases.c.product_id == target_product_id,
                vulnerability_triage.c.triage_state.in_(
                    [TriageState.ACTIVE.value, TriageState.PENDING_APPROVAL.value]
                ),
            )
            .order_by(vulnerability_triage.c.created_at.desc())
        )

        row = conn.execute(stmt.limit(1)).fetchone()
        if not row:
            return None

        m = dict(row._mapping)
        if m.get("created_at") and hasattr(m["created_at"], "isoformat"):
            m["created_at"] = m["created_at"].isoformat()
        exp = m.get("expires_at")
        if exp:
            if hasattr(exp, "strftime"):
                m["expires_at_display"] = exp.strftime("%Y-%m-%d")
                m["expires_at"] = exp.isoformat()
            else:
                m["expires_at_display"] = str(exp)[:10]
        else:
            m["expires_at_display"] = "No Expiration (Indefinite)"

        return m


def get_triage_map_for_report(
    release_asset_id: str | None = None,
) -> dict[str, dict[str, Any]]:
    """Returns a dictionary mapping vulnerability_id and 'vuln_id:package_name' to their latest triage decisions."""
    with get_db_connection() as conn:
        stmt = (
            select(
                asset_vulnerabilities.c.vulnerability_id,
                asset_vulnerabilities.c.package_name,
                vulnerability_triage.c.id.label("triage_id"),
                vulnerability_triage.c.triage_state,
                vulnerability_triage.c.status,
                vulnerability_triage.c.justification,
                vulnerability_triage.c.impact_statement,
                vulnerability_triage.c.expires_at,
                vulnerability_triage.c.created_at,
            )
            .select_from(
                asset_vulnerabilities.join(
                    vulnerability_triage,
                    asset_vulnerabilities.c.id
                    == vulnerability_triage.c.vulnerability_ledger_id,
                )
            )
            .order_by(vulnerability_triage.c.created_at.desc())
        )
        if release_asset_id:
            stmt = stmt.where(
                asset_vulnerabilities.c.release_asset_id == release_asset_id
            )

        rows = conn.execute(stmt).fetchall()
        triage_map: dict[str, dict[str, Any]] = {}
        for r in rows:
            m = dict(r._mapping)
            if m.get("created_at") and hasattr(m["created_at"], "isoformat"):
                m["created_at"] = m["created_at"].isoformat()

            exp = m.get("expires_at")
            if exp:
                if hasattr(exp, "strftime"):
                    m["expires_at_display"] = exp.strftime("%Y-%m-%d")
                    m["expires_at"] = exp.isoformat()
                else:
                    m["expires_at_display"] = str(exp)[:10]
            else:
                m["expires_at_display"] = "No Expiration (Indefinite)"

            key = f"{m['vulnerability_id']}:{m['package_name']}"
            if key not in triage_map:
                triage_map[key] = m
            if m["vulnerability_id"] not in triage_map:
                triage_map[m["vulnerability_id"]] = m

        if release_asset_id:
            # Resolve product_id once for this release_asset to avoid redundant subqueries inside the loop
            pid_stmt = (
                select(releases.c.product_id)
                .select_from(
                    release_assets.join(
                        releases, release_assets.c.release_id == releases.c.id
                    )
                )
                .where(release_assets.c.id == release_asset_id)
            )
            target_product_id = conn.scalar(pid_stmt)

            # Check for findings on this asset that don't have direct triage but have product-level VEX
            vulns_stmt = select(
                asset_vulnerabilities.c.vulnerability_id,
                asset_vulnerabilities.c.package_name,
            ).where(asset_vulnerabilities.c.release_asset_id == release_asset_id)
            asset_vulns = conn.execute(vulns_stmt).fetchall()
            for av in asset_vulns:
                v_id = av._mapping["vulnerability_id"]
                p_name = av._mapping["package_name"]
                key = f"{v_id}:{p_name}"
                if key not in triage_map:
                    prod_vex = get_product_vex_history(
                        v_id, product_id=target_product_id
                    )
                    if prod_vex:
                        triage_map[key] = {
                            "triage_state": "product_vex_available",
                            "status": prod_vex["status"],
                            "justification": prod_vex["justification"],
                            "impact_statement": prod_vex["impact_statement"],
                            "expires_at_display": prod_vex["expires_at_display"],
                            "product_vex": prod_vex,
                        }
                        if v_id not in triage_map:
                            triage_map[v_id] = triage_map[key]

        return triage_map
