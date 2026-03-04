import os
import sqlite3
import uuid
from contextlib import contextmanager
from typing import Any, Generator

# Initialize the jobs database
DB_PATH = os.path.join(os.path.dirname(__file__), "jobs.db")


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
                CREATE TABLE IF NOT EXISTS packages (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(name, version)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS package_assets (
                    id TEXT PRIMARY KEY,
                    package_id TEXT NOT NULL,
                    asset_type TEXT NOT NULL,
                    asset_id TEXT NOT NULL,
                    git_ref TEXT DEFAULT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (package_id) REFERENCES packages(id)
                )
            """)
            conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_pkg_asset_unique 
                ON package_assets(package_id, asset_type, asset_id, IFNULL(git_ref, ''))
            """)


init_db()


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


def add_package(name: str, version: str) -> str:
    package_id = str(uuid.uuid4())
    with get_db_connection() as conn:
        with conn:
            conn.execute(
                "INSERT INTO packages (id, name, version) VALUES (?, ?, ?) ON CONFLICT(name, version) DO UPDATE SET name=excluded.name",
                (package_id, name, version),
            )
            cursor = conn.execute(
                "SELECT id FROM packages WHERE name = ? AND version = ?",
                (name, version),
            )
            row = cursor.fetchone()
            return str(row["id"]) if row else package_id


def get_all_packages() -> list[dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM packages ORDER BY created_at DESC")
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def get_package(package_id: str) -> dict[str, Any] | None:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM packages WHERE id = ?", (package_id,))
        row = cursor.fetchone()
        if row:
            return dict(row)
    return None


def add_package_asset(
    package_id: str, asset_type: str, asset_id: str, git_ref: str | None = None
) -> str:
    pkg_asset_id = str(uuid.uuid4())
    with get_db_connection() as conn:
        with conn:
            # Check if this exact asset mapping (including git_ref) exists
            check_query = "SELECT id FROM package_assets WHERE package_id = ? AND asset_type = ? AND asset_id = ? AND IFNULL(git_ref, '') = ?"
            cursor = conn.execute(
                check_query, (package_id, asset_type, asset_id, git_ref or "")
            )
            row = cursor.fetchone()
            if row:
                return str(row["id"])

            # Insert new mapping if it does not precisely exist
            conn.execute(
                "INSERT INTO package_assets (id, package_id, asset_type, asset_id, git_ref) VALUES (?, ?, ?, ?, ?)",
                (pkg_asset_id, package_id, asset_type, asset_id, git_ref),
            )
            return pkg_asset_id


def remove_package_asset(package_asset_id: str) -> None:
    with get_db_connection() as conn:
        with conn:
            conn.execute("DELETE FROM package_assets WHERE id = ?", (package_asset_id,))


def get_package_assets_with_latest_scans(package_id: str) -> list[dict[str, Any]]:
    query = """
    WITH LatestScans AS (
        SELECT sj.*, ROW_NUMBER() OVER(PARTITION BY sj.target_url, sj.target_type, IFNULL(sj.git_ref, '') ORDER BY sj.created_at DESC) as rn
        FROM scan_jobs sj
    )
    SELECT 
        pa.id as package_asset_id,
        pa.asset_type,
        pa.asset_id,
        pa.git_ref,
        CASE 
            WHEN pa.asset_type = 'repo' THEN r.url
            WHEN pa.asset_type = 'image' THEN i.name
        END as asset_name,
        ls.id as latest_scan_id,
        ls.status as latest_scan_status,
        ls.created_at as latest_scan_time,
        ls.results_json,
        ls.resolved_commit,
        ls.resolved_tags
    FROM package_assets pa
    LEFT JOIN repositories r ON pa.asset_type = 'repo' AND pa.asset_id = r.id
    LEFT JOIN images i ON pa.asset_type = 'image' AND pa.asset_id = i.id
    LEFT JOIN LatestScans ls ON 
        (ls.rn = 1) AND 
        (ls.target_url = CASE WHEN pa.asset_type = 'repo' THEN r.url ELSE i.name END) AND
        (ls.target_type = pa.asset_type) AND
        (IFNULL(ls.git_ref, '') = IFNULL(pa.git_ref, ''))
    WHERE pa.package_id = ?
    ORDER BY pa.created_at DESC
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, (package_id,))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
