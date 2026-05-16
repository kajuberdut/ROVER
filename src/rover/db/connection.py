import os
from contextlib import contextmanager
from typing import Generator
from sqlalchemy import create_engine, Connection
from sqlalchemy.event import listen

DATABASE_URL = os.environ.get(
    "DATABASE_URL", 
    "postgresql+psycopg://rover:rover_password@db:5432/rover"
)

# Initialize engine. Can be overridden in tests.
engine = create_engine(DATABASE_URL)

@contextmanager
def get_db_connection() -> Generator[Connection, None, None]:
    """
    Centralized connection context manager using SQLAlchemy Core.
    Yields an active transaction connection via engine.begin().
    """
    with engine.begin() as conn:
        yield conn
