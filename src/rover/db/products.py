import logging
import uuid
from typing import Any

from sqlalchemy import delete, insert, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql import func

from rover.db.connection import get_db_connection
from rover.db.schema import product_users, products, release_assets, releases

logger = logging.getLogger(__name__)


def add_product(name: str, description: str = "") -> str:
    product_id = str(uuid.uuid4())
    try:
        with get_db_connection() as conn:
            conn.execute(
                insert(products).values(
                    id=product_id, name=name, description=description
                )
            )
            return product_id
    except IntegrityError:
        with get_db_connection() as conn:
            conn.execute(
                update(products)
                .where(products.c.name == name)
                .values(description=description)
            )
            row = conn.execute(
                select(products.c.id).where(products.c.name == name)
            ).fetchone()
            return str(row[0]) if row else product_id


def get_all_products() -> list[dict[str, Any]]:
    with get_db_connection() as conn:
        rows = conn.execute(select(products).order_by(products.c.name.asc())).fetchall()
        return [dict(row._mapping) for row in rows]


def get_product(product_id: str) -> dict[str, Any] | None:
    with get_db_connection() as conn:
        row = conn.execute(
            select(products).where(products.c.id == product_id)
        ).fetchone()
        return dict(row._mapping) if row else None


def add_release(product_id: str, name: str, version: str) -> str:
    release_id = str(uuid.uuid4())
    try:
        with get_db_connection() as conn:
            conn.execute(
                insert(releases).values(
                    id=release_id, product_id=product_id, name=name, version=version
                )
            )
            return release_id
    except IntegrityError:
        with get_db_connection() as conn:
            conn.execute(
                update(releases)
                .where(releases.c.name == name, releases.c.version == version)
                .values(name=name)  # update anything if needed, just a touch
            )
            row = conn.execute(
                select(releases.c.id).where(
                    releases.c.name == name, releases.c.version == version
                )
            ).fetchone()
            return str(row[0]) if row else release_id


def get_all_releases() -> list[dict[str, Any]]:
    with get_db_connection() as conn:
        rows = conn.execute(
            select(releases)
            .where(releases.c.is_end_of_life == False)
            .order_by(releases.c.created_at.desc())
        ).fetchall()
        return [dict(row._mapping) for row in rows]


def get_product_releases(product_id: str) -> list[dict[str, Any]]:
    with get_db_connection() as conn:
        rows = conn.execute(
            select(releases)
            .where(releases.c.product_id == product_id)
            .order_by(releases.c.version.desc())
        ).fetchall()
        return [dict(row._mapping) for row in rows]


def update_release_eol_status(release_id: str, is_eol: bool) -> None:
    with get_db_connection() as conn:
        conn.execute(
            update(releases)
            .where(releases.c.id == release_id)
            .values(is_end_of_life=is_eol)
        )


def get_release(release_id: str) -> dict[str, Any] | None:
    with get_db_connection() as conn:
        row = conn.execute(
            select(releases).where(releases.c.id == release_id)
        ).fetchone()
        return dict(row._mapping) if row else None


def delete_release(release_id: str) -> None:
    with get_db_connection() as conn:
        conn.execute(
            delete(release_assets).where(release_assets.c.release_id == release_id)
        )
        conn.execute(delete(releases).where(releases.c.id == release_id))


def delete_product(product_id: str) -> None:
    releases_list = get_product_releases(product_id)
    for r in releases_list:
        delete_release(r["id"])
    with get_db_connection() as conn:
        conn.execute(
            delete(product_users).where(product_users.c.product_id == product_id)
        )
        conn.execute(delete(products).where(products.c.id == product_id))


def add_release_asset(
    release_id: str, asset_type: str, asset_id: str, git_ref: str | None = None
) -> str:
    rel_asset_id = str(uuid.uuid4())
    with get_db_connection() as conn:
        row = conn.execute(
            select(release_assets.c.id).where(
                release_assets.c.release_id == release_id,
                release_assets.c.asset_type == asset_type,
                release_assets.c.asset_id == asset_id,
                # SQLite handles NULL == NULL poorly in some dialects, but coalesce is standard
                func.coalesce(release_assets.c.git_ref, "") == (git_ref or ""),
            )
        ).fetchone()
        if row:
            return str(row[0])

        conn.execute(
            insert(release_assets).values(
                id=rel_asset_id,
                release_id=release_id,
                asset_type=asset_type,
                asset_id=asset_id,
                git_ref=git_ref,
            )
        )
        return rel_asset_id


def remove_release_asset(release_asset_id: str) -> None:
    with get_db_connection() as conn:
        conn.execute(
            delete(release_assets).where(release_assets.c.id == release_asset_id)
        )


def get_release_asset(release_asset_id: str) -> dict[str, Any] | None:
    with get_db_connection() as conn:
        row = conn.execute(
            select(release_assets).where(release_assets.c.id == release_asset_id)
        ).fetchone()
        return dict(row._mapping) if row else None


def get_release_asset_details(release_asset_id: str) -> dict[str, Any] | None:
    query = text("""
    SELECT 
        pa.id as release_asset_id,
        pa.release_id,
        pa.asset_type,
        pa.asset_id,
        pa.git_ref,
        CASE 
            WHEN pa.asset_type = 'repo' THEN r.url
            WHEN pa.asset_type = 'image' THEN i.name
            WHEN pa.asset_type = 'major_component' THEN e.name
        END as asset_name,
        ci.repo_uri as source_repo_url,
        ci.commit_hash as image_source_git_ref
    FROM release_assets pa
    LEFT JOIN repositories r ON pa.asset_type = 'repo' AND pa.asset_id = r.id
    LEFT JOIN images i ON pa.asset_type = 'image' AND pa.asset_id = i.id
    LEFT JOIN ci_image_metadata ci ON pa.asset_type = 'image' AND i.image_hash = ci.image_hash
    LEFT JOIN major_components e ON pa.asset_type = 'major_component' AND pa.asset_id = e.id
    WHERE pa.id = :release_asset_id
    """)
    with get_db_connection() as conn:
        row = conn.execute(query, {"release_asset_id": release_asset_id}).fetchone()
        return dict(row._mapping) if row else None


def get_product_assets_with_latest_scans(product_id: str) -> list[dict[str, Any]]:
    # Changed IFNULL to COALESCE for cross-database compatibility (PostgreSQL doesn't have IFNULL)
    query = text("""
    WITH LatestScans AS (
        SELECT sj.*, ROW_NUMBER() OVER(PARTITION BY sj.target_url, sj.target_type, COALESCE(sj.git_ref, '') ORDER BY sj.created_at DESC) as rn
        FROM scanner_jobs sj
        WHERE sj.scanner_name = 'trivy'
    )
    SELECT 
        pa.id as release_asset_id,
        pa.asset_type,
        pa.asset_id,
        pa.git_ref,
        CASE 
            WHEN pa.asset_type = 'repo' THEN r.url
            WHEN pa.asset_type = 'image' THEN i.name
            WHEN pa.asset_type = 'major_component' THEN e.name
        END as asset_name,
        ls.id as latest_scan_id,
        ls.status as latest_scan_status,
        ls.created_at as latest_scan_time,
        ls.results_json,
        ls.resolved_commit,
        ls.resolved_tags
    FROM release_assets pa
    JOIN releases pk ON pa.release_id = pk.id
    LEFT JOIN repositories r ON pa.asset_type = 'repo' AND pa.asset_id = r.id
    LEFT JOIN images i ON pa.asset_type = 'image' AND pa.asset_id = i.id
    LEFT JOIN major_components e ON pa.asset_type = 'major_component' AND pa.asset_id = e.id
    LEFT JOIN LatestScans ls ON 
        (ls.rn = 1) AND 
        (ls.target_url = CASE WHEN pa.asset_type = 'repo' THEN r.url WHEN pa.asset_type = 'image' THEN i.name WHEN pa.asset_type = 'major_component' THEN e.name END) AND
        (COALESCE(ls.git_ref, '') = COALESCE(pa.git_ref, ''))
    WHERE pk.product_id = :product_id AND pk.is_end_of_life = false
    """)
    with get_db_connection() as conn:
        rows = conn.execute(query, {"product_id": product_id}).fetchall()
        return [dict(row._mapping) for row in rows]


def get_release_assets_with_latest_scans(release_id: str) -> list[dict[str, Any]]:
    query = text("""
    WITH LatestScans AS (
        SELECT sj.*, ROW_NUMBER() OVER(PARTITION BY sj.target_url, COALESCE(sj.git_ref, '') ORDER BY sj.created_at DESC) as rn
        FROM scanner_jobs sj
        WHERE sj.scanner_name = 'trivy'
    )
    SELECT 
        pa.id as release_asset_id,
        pa.asset_type,
        pa.asset_id,
        CASE 
            WHEN pa.asset_type = 'major_component' THEN COALESCE(pa.git_ref, e.version)
            ELSE pa.git_ref
        END as git_ref,
        CASE 
            WHEN pa.asset_type = 'repo' THEN r.url
            WHEN pa.asset_type = 'image' THEN i.name
            WHEN pa.asset_type = 'major_component' THEN e.name
        END as asset_name,
        ls.id as latest_scan_id,
        ls.status as latest_scan_status,
        ls.created_at as latest_scan_time,
        ls.results_json,
        ls.resolved_commit,
        ls.resolved_tags,
        cim.repo_uri as source_repo_url,
        cim.commit_hash as image_source_git_ref
    FROM release_assets pa
    LEFT JOIN repositories r ON pa.asset_type = 'repo' AND pa.asset_id = r.id
    LEFT JOIN images i ON pa.asset_type = 'image' AND pa.asset_id = i.id
    LEFT JOIN ci_image_metadata cim ON pa.asset_type = 'image' AND i.image_hash = cim.image_hash
    LEFT JOIN major_components e ON pa.asset_type = 'major_component' AND pa.asset_id = e.id
    LEFT JOIN LatestScans ls ON 
        (ls.rn = 1) AND 
        (ls.target_url = CASE WHEN pa.asset_type = 'repo' THEN r.url WHEN pa.asset_type = 'image' THEN i.name WHEN pa.asset_type = 'major_component' THEN e.name END) AND
        (COALESCE(ls.git_ref, '') = COALESCE(pa.git_ref, e.version, ''))
    WHERE pa.release_id = :release_id
    ORDER BY pa.created_at DESC
    """)
    with get_db_connection() as conn:
        rows = conn.execute(query, {"release_id": release_id}).fetchall()
        assets = [dict(row._mapping) for row in rows]

        from rover import plugins

        for asset in assets:
            badges = []
            for plugin in plugins.list_plugins():
                if not plugin.can_handle(asset["asset_type"]):
                    continue

                if (
                    plugin.name == "semgrep"
                    and asset["asset_type"] == "image"
                    and not asset.get("source_repo_url")
                ):
                    continue

                # Check legacy and unified scanner job records
                results = None
                status = None
                err = None

                def _load_res(raw_res: Any) -> Any:
                    if raw_res is None:
                        return None
                    if isinstance(raw_res, (dict, list)):
                        return raw_res
                    if isinstance(raw_res, (str, bytes)):
                        import json

                        try:
                            return json.loads(raw_res)
                        except Exception as exc:
                            logger.debug(f"Failed to parse results_json: {exc}")
                    return None

                if plugin.name == "semgrep":
                    status = asset.get("semgrep_scan_status")
                    err = asset.get("semgrep_error_message")
                    if asset.get("semgrep_results_json"):
                        results = _load_res(asset["semgrep_results_json"])
                elif plugin.name == "snyk":
                    status = asset.get("snyk_scan_status")
                    err = asset.get("snyk_error_message")
                    if asset.get("snyk_results_json"):
                        results = _load_res(asset["snyk_results_json"])
                elif plugin.name == "trivy":
                    status = asset.get("latest_scan_status")
                    if asset.get("results_json"):
                        results = _load_res(asset["results_json"])

                # Also check unified scanner_jobs table
                duration_sec = None
                started_at_val = None
                latest_scan_id_val = None

                target_url = asset.get("asset_name")
                if (
                    plugin.name == "semgrep"
                    and asset["asset_type"] == "image"
                    and asset.get("source_repo_url")
                ):
                    target_url = asset["source_repo_url"]

                if target_url:
                    scanner_job = (
                        conn.execute(
                            text("""
                        SELECT * FROM scanner_jobs
                        WHERE scanner_name = :scanner_name AND target_url = :target_url
                        ORDER BY created_at DESC LIMIT 1
                        """),
                            {"scanner_name": plugin.name, "target_url": target_url},
                        )
                        .mappings()
                        .first()
                    )
                    if scanner_job:
                        status = scanner_job["status"]
                        err = scanner_job.get("error_message")
                        latest_scan_id_val = scanner_job["id"]
                        duration_sec = scanner_job.get("duration_seconds")
                        started_at_val = scanner_job.get("started_at")
                        if scanner_job.get("results_json"):
                            results = _load_res(scanner_job["results_json"])

                # Calculate elapsed time if currently running
                if status == "running" and started_at_val:
                    import datetime

                    if isinstance(started_at_val, datetime.datetime):
                        now = datetime.datetime.now(datetime.timezone.utc)
                        if started_at_val.tzinfo is None:
                            now = datetime.datetime.now()
                        duration_sec = max(
                            0, int((now - started_at_val).total_seconds())
                        )

                from rover.db.jobs import get_average_scan_duration

                avg_sec = get_average_scan_duration(plugin.name, target_url)

                badge_info = plugin.get_badge_info(
                    results,
                    status,
                    error_message=err,
                    duration_seconds=duration_sec,
                    avg_duration_seconds=int(avg_sec) if avg_sec else None,
                )
                badge_info["scanner_name"] = plugin.name
                badge_info["display_name"] = plugin.display_name
                badge_info["icon"] = plugin.icon
                badge_info["latest_scan_id"] = latest_scan_id_val
                badge_info["duration_seconds"] = duration_sec
                badge_info["avg_duration_seconds"] = int(avg_sec) if avg_sec else None
                badges.append(badge_info)

            asset["badges"] = badges

        return assets
