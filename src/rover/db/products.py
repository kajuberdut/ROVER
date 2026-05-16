import uuid
from typing import Any
from sqlalchemy import select, insert, update, delete, text
from sqlalchemy.sql import func
from sqlalchemy.exc import IntegrityError
from rover.db.connection import get_db_connection
from rover.db.schema import products, releases, release_assets, product_users

def add_product(name: str, description: str = "") -> str:
    product_id = str(uuid.uuid4())
    try:
        with get_db_connection() as conn:
            conn.execute(insert(products).values(id=product_id, name=name, description=description))
            return product_id
    except IntegrityError:
        with get_db_connection() as conn:
            conn.execute(update(products).where(products.c.name == name).values(description=description))
            row = conn.execute(select(products.c.id).where(products.c.name == name)).fetchone()
            return str(row[0])

def get_all_products() -> list[dict[str, Any]]:
    with get_db_connection() as conn:
        rows = conn.execute(select(products).order_by(products.c.name.asc())).fetchall()
        return [dict(row._mapping) for row in rows]

def get_product(product_id: str) -> dict[str, Any] | None:
    with get_db_connection() as conn:
        row = conn.execute(select(products).where(products.c.id == product_id)).fetchone()
        return dict(row._mapping) if row else None

def add_release(product_id: str, name: str, version: str) -> str:
    release_id = str(uuid.uuid4())
    try:
        with get_db_connection() as conn:
            conn.execute(insert(releases).values(id=release_id, product_id=product_id, name=name, version=version))
            return release_id
    except IntegrityError:
        with get_db_connection() as conn:
            conn.execute(
                update(releases)
                .where(releases.c.name == name, releases.c.version == version)
                .values(name=name)  # update anything if needed, just a touch
            )
            row = conn.execute(
                select(releases.c.id)
                .where(releases.c.name == name, releases.c.version == version)
            ).fetchone()
            return str(row[0])

def get_all_releases() -> list[dict[str, Any]]:
    with get_db_connection() as conn:
        rows = conn.execute(
            select(releases).where(releases.c.is_end_of_life == False).order_by(releases.c.created_at.desc())
        ).fetchall()
        return [dict(row._mapping) for row in rows]

def get_product_releases(product_id: str) -> list[dict[str, Any]]:
    with get_db_connection() as conn:
        rows = conn.execute(
            select(releases).where(releases.c.product_id == product_id).order_by(releases.c.version.desc())
        ).fetchall()
        return [dict(row._mapping) for row in rows]

def update_release_eol_status(release_id: str, is_eol: bool) -> None:
    with get_db_connection() as conn:
        conn.execute(
            update(releases).where(releases.c.id == release_id).values(is_end_of_life=is_eol)
        )

def get_release(release_id: str) -> dict[str, Any] | None:
    with get_db_connection() as conn:
        row = conn.execute(select(releases).where(releases.c.id == release_id)).fetchone()
        return dict(row._mapping) if row else None

def delete_release(release_id: str) -> None:
    with get_db_connection() as conn:
        conn.execute(delete(release_assets).where(release_assets.c.release_id == release_id))
        conn.execute(delete(releases).where(releases.c.id == release_id))

def delete_product(product_id: str) -> None:
    releases_list = get_product_releases(product_id)
    for r in releases_list:
        delete_release(r["id"])
    with get_db_connection() as conn:
        conn.execute(delete(product_users).where(product_users.c.product_id == product_id))
        conn.execute(delete(products).where(products.c.id == product_id))

def add_release_asset(release_id: str, asset_type: str, asset_id: str, git_ref: str | None = None) -> str:
    rel_asset_id = str(uuid.uuid4())
    with get_db_connection() as conn:
        row = conn.execute(
            select(release_assets.c.id)
            .where(
                release_assets.c.release_id == release_id,
                release_assets.c.asset_type == asset_type,
                release_assets.c.asset_id == asset_id,
                # SQLite handles NULL == NULL poorly in some dialects, but coalesce is standard
                func.coalesce(release_assets.c.git_ref, '') == (git_ref or '')
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
                git_ref=git_ref
            )
        )
        return rel_asset_id

def remove_release_asset(release_asset_id: str) -> None:
    with get_db_connection() as conn:
        conn.execute(delete(release_assets).where(release_assets.c.id == release_asset_id))

def get_release_asset(release_asset_id: str) -> dict[str, Any] | None:
    with get_db_connection() as conn:
        row = conn.execute(select(release_assets).where(release_assets.c.id == release_asset_id)).fetchone()
        return dict(row._mapping) if row else None

def get_product_assets_with_latest_scans(product_id: str) -> list[dict[str, Any]]:
    # Changed IFNULL to COALESCE for cross-database compatibility (PostgreSQL doesn't have IFNULL)
    query = text("""
    WITH LatestScans AS (
        SELECT sj.*, ROW_NUMBER() OVER(PARTITION BY sj.target_url, sj.target_type, COALESCE(sj.git_ref, '') ORDER BY sj.created_at DESC) as rn
        FROM scan_jobs sj
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
        (ls.target_type = pa.asset_type) AND
        (COALESCE(ls.git_ref, '') = COALESCE(pa.git_ref, ''))
    WHERE pk.product_id = :product_id AND pk.is_end_of_life = 0
    """)
    with get_db_connection() as conn:
        rows = conn.execute(query, {"product_id": product_id}).fetchall()
        return [dict(row._mapping) for row in rows]

def get_release_assets_with_latest_scans(release_id: str) -> list[dict[str, Any]]:
    query = text("""
    WITH LatestScans AS (
        SELECT sj.*, ROW_NUMBER() OVER(PARTITION BY sj.target_url, sj.target_type, COALESCE(sj.git_ref, '') ORDER BY sj.created_at DESC) as rn
        FROM scan_jobs sj
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
        (ls.target_type = pa.asset_type) AND
        (COALESCE(ls.git_ref, '') = COALESCE(pa.git_ref, ''))
    WHERE pa.release_id = :release_id
    ORDER BY pa.created_at DESC
    """)
    with get_db_connection() as conn:
        rows = conn.execute(query, {"release_id": release_id}).fetchall()
        return [dict(row._mapping) for row in rows]
