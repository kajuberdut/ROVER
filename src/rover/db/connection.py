import os
import socket
from contextlib import contextmanager
from typing import Generator

from sqlalchemy import Connection, create_engine

_default_url = "postgresql+psycopg://rover:rover_password@db:5432/rover"
try:
    socket.gethostbyname("db")
except Exception:
    _default_url = "postgresql+psycopg://rover:rover_password@localhost:5432/rover"

DATABASE_URL = os.environ.get("DATABASE_URL", _default_url)

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
