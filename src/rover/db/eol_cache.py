import datetime
import uuid

from sqlalchemy import insert, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql import func

from rover.db.connection import get_db_connection
from rover.db.schema import eol_cache


def get_cached_eol_data(name: str, version: str) -> str | None:
    with get_db_connection() as conn:
        threshold = datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=28)
        row = conn.execute(
            select(eol_cache.c.response_json)
            .where(eol_cache.c.name == name, eol_cache.c.version == version)
            .where(eol_cache.c.cached_at >= threshold)
        ).fetchone()
        return str(row[0]) if row else None


def set_cached_eol_data(name: str, version: str, response_json: str) -> None:
    cache_id = str(uuid.uuid4())
    with get_db_connection() as conn:
        row = conn.execute(
            select(eol_cache.c.id).where(
                eol_cache.c.name == name, eol_cache.c.version == version
            )
        ).fetchone()
        if row:
            conn.execute(
                update(eol_cache)
                .where(eol_cache.c.id == row[0])
                .values(response_json=response_json, cached_at=func.current_timestamp())
            )
        else:
            try:
                conn.execute(
                    insert(eol_cache).values(
                        id=cache_id,
                        name=name,
                        version=version,
                        response_json=response_json,
                    )
                )
            except IntegrityError:
                conn.execute(
                    update(eol_cache)
                    .where(eol_cache.c.name == name, eol_cache.c.version == version)
                    .values(
                        response_json=response_json, cached_at=func.current_timestamp()
                    )
                )
