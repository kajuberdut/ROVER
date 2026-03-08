import os
import sqlite3
import uuid
from contextlib import contextmanager
from typing import Any, Generator

# Initialize the jobs database
DB_PATH = os.environ.get(
    "ROVER_DB_PATH", os.path.join(os.path.dirname(__file__), "jobs.db")
)


@contextmanager
def get_db_connection() -> Generator[sqlite3.Connection, None, None]:
    """
    Centralized connection context manager.
    Sets a timeout to wait for locks and enables WAL mode
    (which is required for Litestream and provides great concurrency).
    """
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    try:
        # Enable Write-Ahead Logging
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    with get_db_connection() as conn:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_jobs (
                    id TEXT PRIMARY KEY,
                    target_url TEXT NOT NULL,
                    git_ref TEXT DEFAULT NULL,
                    status TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    results_json TEXT DEFAULT NULL,
                    error_message TEXT DEFAULT NULL,
                    resolved_commit TEXT DEFAULT NULL,
                    resolved_tags TEXT DEFAULT NULL,
                    target_type TEXT DEFAULT 'repo'
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS repositories (
                    id TEXT PRIMARY KEY,
                    url TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS images (
                    id TEXT PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS major_components (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(name, version)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS eol_cache (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    response_json TEXT NOT NULL,
                    cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(name, version)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS products (
                    id TEXT PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    description TEXT DEFAULT '',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS releases (
                    id TEXT PRIMARY KEY,
                    product_id TEXT,
                    name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    is_end_of_life BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(name, version)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS release_assets (
                    id TEXT PRIMARY KEY,
                    release_id TEXT NOT NULL,
                    asset_type TEXT NOT NULL,
                    asset_id TEXT NOT NULL,
                    git_ref TEXT DEFAULT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (release_id) REFERENCES releases(id)
                )
            """)
            conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_rel_asset_unique 
                ON release_assets(release_id, asset_type, asset_id, IFNULL(git_ref, ''))
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    sub        TEXT PRIMARY KEY,
                    email      TEXT,
                    name       TEXT,
                    role       TEXT NOT NULL DEFAULT 'viewer',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS product_owners (
                    user_sub   TEXT NOT NULL REFERENCES users(sub) ON DELETE CASCADE,
                    product_id TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
                    PRIMARY KEY (user_sub, product_id)
                )
            """)


init_db()


# ── User / RBAC helpers ──────────────────────────────────────────────────────

def upsert_user(sub: str, email: str | None, name: str | None) -> dict[str, Any]:
    """Register or refresh a user record on login. Returns the full user row."""
    with get_db_connection() as conn:
        with conn:
            conn.execute(
                """
                INSERT INTO users (sub, email, name, last_login)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(sub) DO UPDATE SET
                    email      = excluded.email,
                    name       = excluded.name,
                    last_login = CURRENT_TIMESTAMP
                """,
                (sub, email, name),
            )
        cursor = conn.execute("SELECT * FROM users WHERE sub = ?", (sub,))
        return dict(cursor.fetchone())


def get_user(sub: str) -> dict[str, Any] | None:
    with get_db_connection() as conn:
        cursor = conn.execute("SELECT * FROM users WHERE sub = ?", (sub,))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_user_by_email(email: str) -> dict[str, Any] | None:
    with get_db_connection() as conn:
        cursor = conn.execute("SELECT * FROM users WHERE email = ?", (email,))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_all_users() -> list[dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.execute(
            "SELECT * FROM users ORDER BY role ASC, name ASC"
        )
        return [dict(row) for row in cursor.fetchall()]


def set_user_role(sub: str, role: str) -> None:
    """Set a user's global role. Role must be viewer | product_owner | admin."""
    if role not in ("viewer", "product_owner", "admin"):
        raise ValueError(f"Invalid role: {role!r}")
    with get_db_connection() as conn:
        with conn:
            conn.execute(
                "UPDATE users SET role = ? WHERE sub = ?", (role, sub)
            )


def get_product_owners(product_id: str) -> list[dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.execute(
            """
            SELECT u.* FROM users u
            JOIN product_owners po ON po.user_sub = u.sub
            WHERE po.product_id = ?
            """,
            (product_id,),
        )
        return [dict(row) for row in cursor.fetchall()]


def user_owns_product(sub: str, product_id: str) -> bool:
    with get_db_connection() as conn:
        cursor = conn.execute(
            "SELECT 1 FROM product_owners WHERE user_sub = ? AND product_id = ?",
            (sub, product_id),
        )
        return cursor.fetchone() is not None


def add_product_owner(sub: str, product_id: str) -> None:
    with get_db_connection() as conn:
        with conn:
            conn.execute(
                "INSERT OR IGNORE INTO product_owners (user_sub, product_id) VALUES (?, ?)",
                (sub, product_id),
            )


def remove_product_owner(sub: str, product_id: str) -> None:
    with get_db_connection() as conn:
        with conn:
            conn.execute(
                "DELETE FROM product_owners WHERE user_sub = ? AND product_id = ?",
                (sub, product_id),
            )


def get_user_product_ids(sub: str) -> list[str]:
    """Returns all product IDs owned by a given user."""
    with get_db_connection() as conn:
        cursor = conn.execute(
            "SELECT product_id FROM product_owners WHERE user_sub = ?", (sub,)
        )
        return [row["product_id"] for row in cursor.fetchall()]


def create_job(
    target_url: str, git_ref: str | None = None, target_type: str = "repo"
) -> str:
    job_id = str(uuid.uuid4())
    with get_db_connection() as conn:
        with conn:
            conn.execute(
                "INSERT INTO scan_jobs (id, target_url, git_ref, status, target_type) VALUES (?, ?, ?, ?, ?)",
                (job_id, target_url, git_ref, "queued", target_type),
            )
    return job_id


def get_job(job_id: str) -> dict[str, Any] | None:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scan_jobs WHERE id = ?", (job_id,))
        row = cursor.fetchone()
        if row:
            return dict(row)
    return None


def update_job_status(
    job_id: str,
    status: str,
    results_json: str | None = None,
    error_message: str | None = None,
    resolved_commit: str | None = None,
    resolved_tags: str | None = None,
) -> None:
    with get_db_connection() as conn:
        with conn:
            conn.execute(
                "UPDATE scan_jobs SET status = ?, results_json = ?, error_message = ?, resolved_commit = ?, resolved_tags = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (
                    status,
                    results_json,
                    error_message,
                    resolved_commit,
                    resolved_tags,
                    job_id,
                ),
            )


def get_all_jobs() -> list[dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scan_jobs ORDER BY created_at DESC")
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def claim_next_job() -> dict[str, Any] | None:
    """
    Atomically claims the next queued job by updating its status to 'running'
    and returning the job details.
    """
    with get_db_connection() as conn:
        with conn:
            # We use BEGIN IMMEDIATE to acquire a write lock before selecting
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, target_url, git_ref, target_type FROM scan_jobs WHERE status = 'queued' ORDER BY created_at ASC LIMIT 1"
            )
            row = cursor.fetchone()

            if row:
                job_id = row["id"]
                conn.execute(
                    "UPDATE scan_jobs SET status = 'running', updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (job_id,),
                )
                return dict(row)
    return None


def add_repository(url: str) -> str:
    repo_id = str(uuid.uuid4())
    with get_db_connection() as conn:
        with conn:
            conn.execute(
                "INSERT INTO repositories (id, url) VALUES (?, ?) ON CONFLICT(url) DO UPDATE SET url=excluded.url",
                (repo_id, url),
            )
            # Retrieve the correct ID since ON CONFLICT might have just updated the existing one
            cursor = conn.execute("SELECT id FROM repositories WHERE url = ?", (url,))
            row = cursor.fetchone()
            return str(row["id"]) if row else repo_id


def get_all_repositories() -> list[dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM repositories ORDER BY created_at DESC")
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def get_repository(repo_id: str) -> dict[str, Any] | None:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM repositories WHERE id = ?", (repo_id,))
        row = cursor.fetchone()
        if row:
            return dict(row)
    return None


def add_image(name: str) -> str:
    image_id = str(uuid.uuid4())
    with get_db_connection() as conn:
        with conn:
            conn.execute(
                "INSERT INTO images (id, name) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET name=excluded.name",
                (image_id, name),
            )
            cursor = conn.execute("SELECT id FROM images WHERE name = ?", (name,))
            row = cursor.fetchone()
            return str(row["id"]) if row else image_id


def get_all_images() -> list[dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM images ORDER BY created_at DESC")
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def get_image(image_id: str) -> dict[str, Any] | None:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM images WHERE id = ?", (image_id,))
        row = cursor.fetchone()
        if row:
            return dict(row)
    return None


def add_major_component(name: str, version: str) -> str:
    component_id = str(uuid.uuid4())
    with get_db_connection() as conn:
        with conn:
            conn.execute(
                "INSERT INTO major_components (id, name, version) VALUES (?, ?, ?) ON CONFLICT(name, version) DO NOTHING",
                (component_id, name, version),
            )
            cursor = conn.execute(
                "SELECT id FROM major_components WHERE name = ? AND version = ?",
                (name, version),
            )
            row = cursor.fetchone()
            return str(row["id"]) if row else component_id


def get_all_major_components() -> list[dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM major_components ORDER BY name ASC, version DESC")
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def get_major_component(component_id: str) -> dict[str, Any] | None:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM major_components WHERE id = ?", (component_id,))
        row = cursor.fetchone()
        if row:
            return dict(row)
    return None


def get_cached_eol_data(name: str, version: str) -> str | None:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        # 28 days validity
        cursor.execute(
            "SELECT response_json FROM eol_cache WHERE name = ? AND version = ? AND cached_at >= datetime('now', '-28 days')",
            (name, version),
        )
        row = cursor.fetchone()
        return row["response_json"] if row else None


def set_cached_eol_data(name: str, version: str, response_json: str) -> None:
    cache_id = str(uuid.uuid4())
    with get_db_connection() as conn:
        with conn:
            conn.execute(
                "INSERT INTO eol_cache (id, name, version, response_json) VALUES (?, ?, ?, ?) ON CONFLICT(name, version) DO UPDATE SET response_json=excluded.response_json, cached_at=CURRENT_TIMESTAMP",
                (cache_id, name, version, response_json),
            )


def add_product(name: str, description: str = "") -> str:
    product_id = str(uuid.uuid4())
    with get_db_connection() as conn:
        with conn:
            conn.execute(
                "INSERT INTO products (id, name, description) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET description=excluded.description",
                (product_id, name, description),
            )
            cursor = conn.execute("SELECT id FROM products WHERE name = ?", (name,))
            row = cursor.fetchone()
            return str(row["id"]) if row else product_id


def get_all_products() -> list[dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM products ORDER BY name ASC")
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def get_product(product_id: str) -> dict[str, Any] | None:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM products WHERE id = ?", (product_id,))
        row = cursor.fetchone()
        if row:
            return dict(row)
    return None


def add_release(product_id: str, name: str, version: str) -> str:
    release_id = str(uuid.uuid4())
    with get_db_connection() as conn:
        with conn:
            conn.execute(
                "INSERT INTO releases (id, product_id, name, version) VALUES (?, ?, ?, ?) ON CONFLICT(name, version) DO UPDATE SET name=excluded.name",
                (release_id, product_id, name, version),
            )
            cursor = conn.execute(
                "SELECT id FROM releases WHERE name = ? AND version = ?",
                (name, version),
            )
            row = cursor.fetchone()
            return str(row["id"]) if row else release_id


def get_all_releases() -> list[dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM releases WHERE is_end_of_life = 0 ORDER BY created_at DESC"
        )
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def get_product_releases(product_id: str) -> list[dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM releases WHERE product_id = ? ORDER BY version DESC",
            (product_id,),
        )
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def update_release_eol_status(release_id: str, is_eol: bool) -> None:
    with get_db_connection() as conn:
        with conn:
            conn.execute(
                "UPDATE releases SET is_end_of_life = ? WHERE id = ?",
                (1 if is_eol else 0, release_id),
            )


def get_release(release_id: str) -> dict[str, Any] | None:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM releases WHERE id = ?", (release_id,))
        row = cursor.fetchone()
        if row:
            return dict(row)
    return None


def add_release_asset(
    release_id: str, asset_type: str, asset_id: str, git_ref: str | None = None
) -> str:
    rel_asset_id = str(uuid.uuid4())
    with get_db_connection() as conn:
        with conn:
            # Check if this exact asset mapping (including git_ref) exists
            check_query = "SELECT id FROM release_assets WHERE release_id = ? AND asset_type = ? AND asset_id = ? AND IFNULL(git_ref, '') = ?"
            cursor = conn.execute(
                check_query, (release_id, asset_type, asset_id, git_ref or "")
            )
            row = cursor.fetchone()
            if row:
                return str(row["id"])

            # Insert new mapping if it does not precisely exist
            conn.execute(
                "INSERT INTO release_assets (id, release_id, asset_type, asset_id, git_ref) VALUES (?, ?, ?, ?, ?)",
                (rel_asset_id, release_id, asset_type, asset_id, git_ref),
            )
            return rel_asset_id


def remove_release_asset(release_asset_id: str) -> None:
    with get_db_connection() as conn:
        with conn:
            conn.execute("DELETE FROM release_assets WHERE id = ?", (release_asset_id,))


def get_product_assets_with_latest_scans(product_id: str) -> list[dict[str, Any]]:
    query = """
    WITH LatestScans AS (
        SELECT sj.*, ROW_NUMBER() OVER(PARTITION BY sj.target_url, sj.target_type, IFNULL(sj.git_ref, '') ORDER BY sj.created_at DESC) as rn
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
        (IFNULL(ls.git_ref, '') = IFNULL(pa.git_ref, ''))
    WHERE pk.product_id = ? AND pk.is_end_of_life = 0
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, (product_id,))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def get_release_assets_with_latest_scans(release_id: str) -> list[dict[str, Any]]:
    query = """
    WITH LatestScans AS (
        SELECT sj.*, ROW_NUMBER() OVER(PARTITION BY sj.target_url, sj.target_type, IFNULL(sj.git_ref, '') ORDER BY sj.created_at DESC) as rn
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
    LEFT JOIN repositories r ON pa.asset_type = 'repo' AND pa.asset_id = r.id
    LEFT JOIN images i ON pa.asset_type = 'image' AND pa.asset_id = i.id
    LEFT JOIN major_components e ON pa.asset_type = 'major_component' AND pa.asset_id = e.id
    LEFT JOIN LatestScans ls ON 
        (ls.rn = 1) AND 
        (ls.target_url = CASE WHEN pa.asset_type = 'repo' THEN r.url WHEN pa.asset_type = 'image' THEN i.name WHEN pa.asset_type = 'major_component' THEN e.name END) AND
        (ls.target_type = pa.asset_type) AND
        (IFNULL(ls.git_ref, '') = IFNULL(pa.git_ref, ''))
    WHERE pa.release_id = ?
    ORDER BY pa.created_at DESC
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, (release_id,))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
