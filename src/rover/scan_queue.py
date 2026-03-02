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
                    resolved_tags TEXT DEFAULT NULL
                )
            """)


init_db()


def create_job(target_url: str, git_ref: str | None = None) -> str:
    job_id = str(uuid.uuid4())
    with get_db_connection() as conn:
        with conn:
            conn.execute(
                "INSERT INTO scan_jobs (id, target_url, git_ref, status) VALUES (?, ?, ?, ?)",
                (job_id, target_url, git_ref, "queued"),
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
                "SELECT id, target_url, git_ref FROM scan_jobs WHERE status = 'queued' ORDER BY created_at ASC LIMIT 1"
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
