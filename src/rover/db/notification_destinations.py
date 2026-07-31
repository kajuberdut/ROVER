"""src/rover/db/notification_destinations.py — Database and OpenBao operations for managing notification destinations."""

import json
import uuid
from typing import Any

from sqlalchemy import delete, select, update
from sqlalchemy.sql import func

from rover.db.connection import get_db_connection
from rover.db.schema import notification_destinations
from rover.vault import OpenBaoClient


def _build_destination_vault_path(dest_id: str) -> str:
    return f"kv/data/rover/notifications/destinations/{dest_id}"


def set_default_smtp_destination(dest_id: str) -> None:
    """Sets a specific email destination (SMTP or AWS SES) as the default System Email gateway."""
    dest = get_notification_destination_by_id(dest_id)
    if not dest or dest.get("type") not in ("smtp", "aws_ses"):
        raise ValueError(
            "Only SMTP or AWS SES email destinations can be set as system default."
        )

    with get_db_connection() as conn:
        conn.execute(
            update(notification_destinations)
            .where(notification_destinations.c.type.in_(["smtp", "aws_ses"]))
            .values(is_default=False)
        )
        conn.execute(
            update(notification_destinations)
            .where(notification_destinations.c.id == dest_id)
            .values(is_default=True)
        )


def get_default_smtp_destination() -> dict[str, Any] | None:
    """Returns the default System Email destination (SMTP or AWS SES), falling back to the first available email destination."""
    dests = get_notification_destinations()
    for d in dests:
        if d.get("is_default") and d.get("type") in ("smtp", "aws_ses"):
            return d
    for d in dests:
        if d.get("type") in ("smtp", "aws_ses"):
            return d
    return None


def add_notification_destination(
    name: str,
    destination_type: str,
    scope: str,
    config_dict: dict[str, Any] | None = None,
    secret_value: str | dict[str, Any] | None = None,
    user_sub: str | None = None,
    product_id: str | None = None,
    is_system: bool = False,
    is_default: bool = False,
    vault_client: OpenBaoClient | None = None,
) -> dict[str, Any]:
    """Creates a new notification destination record in DB and stores sensitive credentials in OpenBao Vault."""
    dest_id = str(uuid.uuid4())
    config_dict = config_dict or {}
    config_json = json.dumps(config_dict)

    if destination_type not in ("smtp", "aws_ses"):
        is_default = False

    if is_default:
        with get_db_connection() as conn:
            conn.execute(
                update(notification_destinations)
                .where(notification_destinations.c.type.in_(["smtp", "aws_ses"]))
                .values(is_default=False)
            )

    vault_path: str | None = None
    if secret_value:
        client = vault_client or OpenBaoClient()
        vault_path = _build_destination_vault_path(dest_id)
        if isinstance(secret_value, str):
            secret_data = {"secret": secret_value}
        else:
            secret_data = secret_value
        client.write_secret(vault_path, secret_data)

    with get_db_connection() as conn:
        conn.execute(
            notification_destinations.insert().values(
                id=dest_id,
                name=name,
                type=destination_type,
                scope=scope,
                user_sub=user_sub if scope == "user" else None,
                product_id=product_id if scope == "product" else None,
                is_system=is_system or (scope == "system"),
                is_default=is_default,
                config_json=config_json,
                vault_secret_path=vault_path,
            )
        )

    res = get_notification_destination_by_id(dest_id)
    if res is None:
        raise RuntimeError(f"Failed to retrieve newly created destination {dest_id}")
    return res


def get_notification_destinations(
    scope: str | None = None,
    product_id: str | None = None,
    user_sub: str | None = None,
) -> list[dict[str, Any]]:
    """Returns notification destinations matching optional filters (scope, product_id, user_sub)."""
    with get_db_connection() as conn:
        stmt = select(notification_destinations)
        if scope:
            stmt = stmt.where(notification_destinations.c.scope == scope)
        if product_id:
            stmt = stmt.where(notification_destinations.c.product_id == product_id)
        if user_sub:
            stmt = stmt.where(notification_destinations.c.user_sub == user_sub)

        stmt = stmt.order_by(notification_destinations.c.created_at.desc())
        rows = conn.execute(stmt).fetchall()

        results = []
        for r in rows:
            d = dict(r._mapping)
            if hasattr(d.get("created_at"), "isoformat"):
                d["created_at"] = d["created_at"].isoformat()
            elif d.get("created_at") is not None:
                d["created_at"] = str(d["created_at"])
            if hasattr(d.get("updated_at"), "isoformat"):
                d["updated_at"] = d["updated_at"].isoformat()
            elif d.get("updated_at") is not None:
                d["updated_at"] = str(d["updated_at"])

            if isinstance(d.get("config_json"), str):
                try:
                    d["config"] = json.loads(d["config_json"])
                except Exception:
                    d["config"] = {}
            else:
                d["config"] = {}
            results.append(d)
        return results


def get_notification_destination_by_id(dest_id: str) -> dict[str, Any] | None:
    """Retrieves a single notification destination record by ID."""
    with get_db_connection() as conn:
        row = conn.execute(
            select(notification_destinations).where(
                notification_destinations.c.id == dest_id
            )
        ).fetchone()
        if not row:
            return None
        d = dict(row._mapping)
        if hasattr(d.get("created_at"), "isoformat"):
            d["created_at"] = d["created_at"].isoformat()
        elif d.get("created_at") is not None:
            d["created_at"] = str(d["created_at"])
        if hasattr(d.get("updated_at"), "isoformat"):
            d["updated_at"] = d["updated_at"].isoformat()
        elif d.get("updated_at") is not None:
            d["updated_at"] = str(d["updated_at"])

        if isinstance(d.get("config_json"), str):
            try:
                d["config"] = json.loads(d["config_json"])
            except Exception:
                d["config"] = {}
        else:
            d["config"] = {}
        return d


def get_destination_unmasked_secret(
    dest_id: str,
    vault_client: OpenBaoClient | None = None,
) -> dict[str, Any] | None:
    """Retrieves unmasked secret dictionary from OpenBao Vault for a notification destination."""
    dest = get_notification_destination_by_id(dest_id)
    if not dest or not dest.get("vault_secret_path"):
        return None

    client = vault_client or OpenBaoClient()
    return client.read_secret(dest["vault_secret_path"])


def update_notification_destination(
    dest_id: str,
    name: str | None = None,
    config_dict: dict[str, Any] | None = None,
    secret_value: str | dict[str, Any] | None = None,
    is_default: bool | None = None,
    vault_client: OpenBaoClient | None = None,
) -> dict[str, Any] | None:
    """Updates non-sensitive fields and/or OpenBao Vault secret for a notification destination."""
    dest = get_notification_destination_by_id(dest_id)
    if not dest:
        return None

    values: dict[str, Any] = {"updated_at": func.current_timestamp()}
    if name is not None:
        values["name"] = name
    if config_dict is not None:
        values["config_json"] = json.dumps(config_dict)

    if is_default is True:
        if dest.get("type") in ("smtp", "aws_ses"):
            set_default_smtp_destination(dest_id)
        values["is_default"] = True
    elif is_default is False:
        values["is_default"] = False

    vault_path = dest.get("vault_secret_path")
    if secret_value is not None:
        client = vault_client or OpenBaoClient()
        if not vault_path:
            vault_path = _build_destination_vault_path(dest_id)
            values["vault_secret_path"] = vault_path

        if isinstance(secret_value, str):
            secret_data = {"secret": secret_value}
        else:
            secret_data = secret_value
        client.write_secret(vault_path, secret_data)

    with get_db_connection() as conn:
        conn.execute(
            update(notification_destinations)
            .where(notification_destinations.c.id == dest_id)
            .values(**values)
        )

    return get_notification_destination_by_id(dest_id)


def delete_notification_destination(
    dest_id: str,
    vault_client: OpenBaoClient | None = None,
) -> bool:
    """Deletes notification destination record from DB and destroys secret in OpenBao Vault."""
    dest = get_notification_destination_by_id(dest_id)
    if not dest:
        return False

    if dest.get("vault_secret_path"):
        client = vault_client or OpenBaoClient()
        client.delete_secret(dest["vault_secret_path"])

    with get_db_connection() as conn:
        conn.execute(
            delete(notification_destinations).where(
                notification_destinations.c.id == dest_id
            )
        )
    return True
