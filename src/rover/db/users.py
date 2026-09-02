from typing import Any

from sqlalchemy import delete, insert, select, update
from sqlalchemy.sql import func

from rover.db.connection import get_db_connection
from rover.db.schema import (
    api_tokens,
    notification_destinations,
    notification_rules,
    product_users,
    user_invites,
    users,
)


def upsert_user(
    sub: str, email: str | None, name: str | None, role: str | None = None
) -> dict[str, Any]:
    with get_db_connection() as conn:
        row = conn.execute(select(users).where(users.c.sub == sub)).fetchone()
        if not row and email:
            row = conn.execute(select(users).where(users.c.email == email)).fetchone()

        if row:
            target_sub = row.sub
            if target_sub != sub:
                # Update foreign key references in dependent tables before updating primary key sub
                conn.execute(
                    update(product_users)
                    .where(product_users.c.user_sub == target_sub)
                    .values(user_sub=sub)
                )
                conn.execute(
                    update(api_tokens)
                    .where(api_tokens.c.user_sub == target_sub)
                    .values(user_sub=sub)
                )
                conn.execute(
                    update(user_invites)
                    .where(user_invites.c.accepted_by_sub == target_sub)
                    .values(accepted_by_sub=sub)
                )
                conn.execute(
                    update(user_invites)
                    .where(user_invites.c.invited_by_sub == target_sub)
                    .values(invited_by_sub=sub)
                )
                conn.execute(
                    update(notification_destinations)
                    .where(notification_destinations.c.user_sub == target_sub)
                    .values(user_sub=sub)
                )
                conn.execute(
                    update(notification_rules)
                    .where(notification_rules.c.user_sub == target_sub)
                    .values(user_sub=sub)
                )

            update_vals: dict[str, Any] = {
                "sub": sub,
                "email": email,
                "name": name,
                "last_login": func.current_timestamp(),
            }
            if role is not None:
                update_vals["role"] = role
            conn.execute(
                update(users).where(users.c.sub == target_sub).values(**update_vals)
            )
        else:
            insert_vals: dict[str, Any] = {
                "sub": sub,
                "email": email,
                "name": name,
                "last_login": func.current_timestamp(),
            }
            if role is not None:
                insert_vals["role"] = role
            conn.execute(insert(users).values(**insert_vals))
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


def ensure_email_only_user(email: str, is_verified: bool = False) -> dict[str, Any]:
    """Ensures an email_only user account exists for a given email address."""
    import uuid

    clean_email = email.strip()
    user = get_user_by_email(clean_email)
    if not user:
        sub = f"email_{uuid.uuid4().hex[:12]}"
        user = upsert_user(
            sub=sub,
            email=clean_email,
            name=clean_email.split("@")[0],
            role="email_only",
        )
        if is_verified:
            set_user_verified(clean_email, True)
            user["is_verified"] = True
    elif is_verified and not user.get("is_verified"):
        set_user_verified(clean_email, True)
        user["is_verified"] = True
    return user


def get_all_users() -> list[dict[str, Any]]:
    with get_db_connection() as conn:
        rows = conn.execute(
            select(users).order_by(users.c.role.asc(), users.c.name.asc())
        ).fetchall()
        return [dict(row._mapping) for row in rows]


def set_user_role(sub: str, role: str) -> None:
    if role not in ("viewer", "system_admin", "email_only"):
        raise ValueError(f"Invalid role: {role!r}")
    with get_db_connection() as conn:
        conn.execute(update(users).where(users.c.sub == sub).values(role=role))


def set_user_verified(sub: str, is_verified: bool = True) -> None:
    """Sets the is_verified status for a user by sub or email."""
    with get_db_connection() as conn:
        conn.execute(
            update(users)
            .where((users.c.sub == sub) | (users.c.email == sub))
            .values(is_verified=is_verified)
        )


def update_user_password(sub_or_email: str, password_hash: str) -> None:
    """Updates the password hash for a user by sub or email."""
    with get_db_connection() as conn:
        conn.execute(
            update(users)
            .where((users.c.sub == sub_or_email) | (users.c.email == sub_or_email))
            .values(password_hash=password_hash)
        )


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
    valid_roles = ("admin", "write", "read_write", "view", "read", "none")
    if role not in valid_roles:
        raise ValueError(f"Invalid product role: {role!r}")

    with get_db_connection() as conn:
        if role in ("none", "view", "read"):
            conn.execute(
                delete(product_users).where(
                    product_users.c.user_sub == sub,
                    product_users.c.product_id == product_id,
                )
            )
            return

        normalized_role = "write" if role == "read_write" else role
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
                .values(role=normalized_role)
            )
        else:
            conn.execute(
                insert(product_users).values(
                    user_sub=sub, product_id=product_id, role=normalized_role
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
