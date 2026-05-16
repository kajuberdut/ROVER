import os
from contextlib import contextmanager
from typing import Generator
from sqlalchemy import create_engine, Connection
from sqlalchemy.event import listen

# Initialize the jobs database
DB_PATH = os.environ.get(
    "ROVER_DB_PATH", os.path.join(os.path.dirname(os.path.dirname(__file__)), "jobs.db")
)

# Phase 1: SQLite engine
engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"timeout": 10.0})

def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.execute("PRAGMA synchronous=NORMAL;")
    cursor.close()

listen(engine, 'connect', set_sqlite_pragma)

@contextmanager
def get_db_connection() -> Generator[Connection, None, None]:
    """
    Centralized connection context manager using SQLAlchemy Core.
    Yields an active transaction connection via engine.begin().
    """
    with engine.begin() as conn:
        yield conn
