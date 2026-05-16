from typing import Any

from sqlalchemy import delete, insert, select, update
from sqlalchemy.sql import func

from rover.db.connection import get_db_connection
from rover.db.schema import product_users, users


def upsert_user(sub: str, email: str | None, name: str | None) -> dict[str, Any]:
    with get_db_connection() as conn:
        row = conn.execute(select(users).where(users.c.sub == sub)).fetchone()
        if row:
            conn.execute(
                update(users)
                .where(users.c.sub == sub)
                .values(email=email, name=name, last_login=func.current_timestamp())
            )
        else:
            conn.execute(
                insert(users).values(
                    sub=sub, email=email, name=name, last_login=func.current_timestamp()
                )
            )
        row = conn.execute(select(users).where(users.c.sub == sub)).fetchone()
        return dict(row._mapping) if row else {}


def get_user(sub: str) -> dict[str, Any] | None:
    with get_db_connection() as conn:
        row = conn.execute(select(users).where(users.c.sub == sub)).fetchone()
        return dict(row._mapping) if row else None


def get_user_by_email(email: str) -> dict[str, Any] | None:
    with get_db_connection() as conn:
        row = conn.execute(select(users).where(users.c.email == email)).fetchone()
        return dict(row._mapping) if row else None


def get_all_users() -> list[dict[str, Any]]:
    with get_db_connection() as conn:
        rows = conn.execute(
            select(users).order_by(users.c.role.asc(), users.c.name.asc())
        ).fetchall()
        return [dict(row._mapping) for row in rows]


def set_user_role(sub: str, role: str) -> None:
    if role not in ("viewer", "system_admin"):
        raise ValueError(f"Invalid role: {role!r}")
    with get_db_connection() as conn:
        conn.execute(update(users).where(users.c.sub == sub).values(role=role))


def get_product_users(product_id: str) -> list[dict[str, Any]]:
    with get_db_connection() as conn:
        stmt = (
            select(users, product_users.c.role.label("product_role"))
            .select_from(
                users.join(product_users, users.c.sub == product_users.c.user_sub)
            )
            .where(product_users.c.product_id == product_id)
        )
        rows = conn.execute(stmt).fetchall()
        return [dict(row._mapping) for row in rows]


def get_user_product_role(sub: str, product_id: str) -> str | None:
    with get_db_connection() as conn:
        row = conn.execute(
            select(product_users.c.role).where(
                product_users.c.user_sub == sub,
                product_users.c.product_id == product_id,
            )
        ).fetchone()
        return row[0] if row else None


def set_product_user_role(sub: str, product_id: str, role: str) -> None:
    if role not in ("admin", "read_write", "read"):
        raise ValueError(f"Invalid product role: {role!r}")
    with get_db_connection() as conn:
        row = conn.execute(
            select(product_users.c.role).where(
                product_users.c.user_sub == sub,
                product_users.c.product_id == product_id,
            )
        ).fetchone()
        if row:
            conn.execute(
                update(product_users)
                .where(
                    product_users.c.user_sub == sub,
                    product_users.c.product_id == product_id,
                )
                .values(role=role)
            )
        else:
            conn.execute(
                insert(product_users).values(
                    user_sub=sub, product_id=product_id, role=role
                )
            )


def remove_product_user(sub: str, product_id: str) -> None:
    with get_db_connection() as conn:
        conn.execute(
            delete(product_users).where(
                product_users.c.user_sub == sub,
                product_users.c.product_id == product_id,
            )
        )


def get_user_product_ids(sub: str) -> list[str]:
    with get_db_connection() as conn:
        rows = conn.execute(
            select(product_users.c.product_id).where(product_users.c.user_sub == sub)
        ).fetchall()
        return [row[0] for row in rows]
