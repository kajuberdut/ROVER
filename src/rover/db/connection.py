import os
from contextlib import contextmanager
from typing import Generator
from sqlalchemy import create_engine, Connection
from sqlalchemy.event import listen

DATABASE_URL = os.environ.get(
    "DATABASE_URL", 
    f"sqlite:///{os.path.join(os.path.dirname(os.path.dirname(__file__)), 'jobs.db')}"
)

# Initialize engine. Can be overridden in tests.
engine = create_engine(DATABASE_URL)

if DATABASE_URL.startswith("sqlite"):
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
