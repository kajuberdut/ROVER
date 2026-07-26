import uuid
from typing import Any

from sqlalchemy import insert, select, update
from sqlalchemy.exc import IntegrityError

from rover.db.connection import get_db_connection
from rover.db.schema import images, major_components, repositories


def add_repository(url: str) -> str:
    repo_id = str(uuid.uuid4())
    try:
        with get_db_connection() as conn:
            conn.execute(insert(repositories).values(id=repo_id, url=url))
            return repo_id
    except IntegrityError:
        with get_db_connection() as conn:
            row = conn.execute(
                select(repositories.c.id).where(repositories.c.url == url)
            ).fetchone()
            return str(row[0]) if row else repo_id


def get_all_repositories() -> list[dict[str, Any]]:
    with get_db_connection() as conn:
        rows = conn.execute(
            select(repositories).order_by(repositories.c.created_at.desc())
        ).fetchall()
        return [dict(row._mapping) for row in rows]


def get_repository(repo_id: str) -> dict[str, Any] | None:
    with get_db_connection() as conn:
        row = conn.execute(
            select(repositories).where(repositories.c.id == repo_id)
        ).fetchone()
        return dict(row._mapping) if row else None


def add_image(name: str) -> str:
    image_id = str(uuid.uuid4())
    try:
        with get_db_connection() as conn:
            conn.execute(insert(images).values(id=image_id, name=name))
            return image_id
    except IntegrityError:
        with get_db_connection() as conn:
            row = conn.execute(
                select(images.c.id).where(images.c.name == name)
            ).fetchone()
            return str(row[0]) if row else image_id


def get_all_images() -> list[dict[str, Any]]:
    with get_db_connection() as conn:
        rows = conn.execute(
            select(images).order_by(images.c.created_at.desc())
        ).fetchall()
        return [dict(row._mapping) for row in rows]


def get_image(image_id: str) -> dict[str, Any] | None:
    with get_db_connection() as conn:
        row = conn.execute(select(images).where(images.c.id == image_id)).fetchone()
        return dict(row._mapping) if row else None


def get_image_by_name(image_name: str) -> dict[str, Any] | None:
    with get_db_connection() as conn:
        row = conn.execute(select(images).where(images.c.name == image_name)).fetchone()
        return dict(row._mapping) if row else None


def update_image_hash(image_id: str, image_hash: str) -> None:
    with get_db_connection() as conn:
        conn.execute(
            update(images).where(images.c.id == image_id).values(image_hash=image_hash)
        )


def add_major_component(name: str, version: str) -> str:
    component_id = str(uuid.uuid4())
    try:
        with get_db_connection() as conn:
            conn.execute(
                insert(major_components).values(
                    id=component_id, name=name, version=version
                )
            )
            return component_id
    except IntegrityError:
        with get_db_connection() as conn:
            row = conn.execute(
                select(major_components.c.id).where(
                    major_components.c.name == name,
                    major_components.c.version == version,
                )
            ).fetchone()
            return str(row[0]) if row else component_id


def get_all_major_components() -> list[dict[str, Any]]:
    with get_db_connection() as conn:
        rows = conn.execute(
            select(major_components).order_by(
                major_components.c.name.asc(), major_components.c.version.desc()
            )
        ).fetchall()
        return [dict(row._mapping) for row in rows]
