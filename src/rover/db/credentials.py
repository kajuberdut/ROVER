"""src/rover/db/credentials.py — Database and OpenBao operations for managing credentials."""

import uuid
from typing import Any

from sqlalchemy import delete, text

from rover.db.connection import get_db_connection
from rover.db.schema import credentials
from rover.vault import OpenBaoClient

MASKED_SECRET_VALUE = "••••••••"  # noqa: S105


def _build_vault_path(name: str, scope: str, product_id: str | None = None) -> str:
    if scope == "product" and product_id:
        return f"kv/data/rover/credentials/product/{product_id}/{name}"
    return f"kv/data/rover/credentials/system/{name}"


def add_credential(
    name: str,
    credential_type: str,
    scope: str,
    secret_value: str,
    product_id: str | None = None,
    description: str | None = None,
    vault_client: OpenBaoClient | None = None,
) -> dict[str, Any]:
    client = vault_client or OpenBaoClient()
    cred_id = str(uuid.uuid4())
    vault_path = _build_vault_path(name, scope, product_id)

    # 1. Write secret value to OpenBao
    client.write_secret(
        vault_path,
        {
            "name": name,
            "type": credential_type,
            "scope": scope,
            "product_id": product_id or "",
            "value": secret_value,
        },
    )

    # 2. Save metadata record to DB
    with get_db_connection() as conn:
        conn.execute(
            credentials.insert().values(
                id=cred_id,
                name=name,
                type=credential_type,
                scope=scope,
                product_id=product_id if scope == "product" else None,
                description=description,
            )
        )

    return get_credential_by_id(cred_id)  # type: ignore # returns masked dict


def get_credentials(product_id: str | None = None) -> list[dict[str, Any]]:
    if product_id:
        query = text("""
        SELECT 
            c.id, c.name, c.type, c.scope, c.product_id, c.description, c.created_at, c.updated_at,
            p.name as product_name
        FROM credentials c
        LEFT JOIN products p ON c.product_id = p.id
        WHERE c.product_id = :product_id OR c.scope = 'system'
        ORDER BY c.created_at DESC
        """)
        params: dict[str, Any] = {"product_id": product_id}
    else:
        query = text("""
        SELECT 
            c.id, c.name, c.type, c.scope, c.product_id, c.description, c.created_at, c.updated_at,
            p.name as product_name
        FROM credentials c
        LEFT JOIN products p ON c.product_id = p.id
        ORDER BY c.created_at DESC
        """)
        params = {}

    with get_db_connection() as conn:
        rows = conn.execute(query, params).fetchall()
        result = []
        for r in rows:
            d = dict(r._mapping)
            d["masked_value"] = MASKED_SECRET_VALUE
            result.append(d)
        return result


def get_credential_by_id(cred_id: str) -> dict[str, Any] | None:
    query = text("""
    SELECT 
        c.id, c.name, c.type, c.scope, c.product_id, c.description, c.created_at, c.updated_at,
        p.name as product_name
    FROM credentials c
    LEFT JOIN products p ON c.product_id = p.id
    WHERE c.id = :id
    """)
    with get_db_connection() as conn:
        row = conn.execute(query, {"id": cred_id}).fetchone()
        if not row:
            return None
        d = dict(row._mapping)
        d["masked_value"] = MASKED_SECRET_VALUE
        return d


def get_unmasked_secret(
    name: str,
    scope: str = "system",
    product_id: str | None = None,
    vault_client: OpenBaoClient | None = None,
) -> str | None:
    """Fetches unmasked secret string from OpenBao for scanner container injection."""
    client = vault_client or OpenBaoClient()
    vault_path = _build_vault_path(name, scope, product_id)
    data = client.read_secret(vault_path)
    if data and "value" in data:
        return str(data["value"])

    # Fallback to system scope if product override not found
    if scope == "product" and product_id:
        fallback_path = _build_vault_path(name, "system", None)
        fallback_data = client.read_secret(fallback_path)
        if fallback_data and "value" in fallback_data:
            return str(fallback_data["value"])

    return None


def get_unmasked_secret_by_type_info(
    credential_type: str,
    hostname: str | None = None,
    product_id: str | None = None,
    vault_client: OpenBaoClient | None = None,
) -> tuple[str | None, dict[str, Any] | None]:
    """Fetches unmasked secret and metadata dictionary from OpenBao by credential type or name."""
    # 1. Search DB credentials table for matching records
    with get_db_connection() as conn:
        if product_id:
            query = text("""
                SELECT id, name, type, scope, product_id FROM credentials
                WHERE product_id = :product_id
                  AND (type = :type OR type = 'git_token' OR type = 'github_token' OR name = :hostname OR name = :type)
                ORDER BY created_at DESC
            """)
            rows = conn.execute(
                query,
                {"product_id": product_id, "type": credential_type, "hostname": hostname or ""},
            ).fetchall()
            for r in rows:
                sec = get_unmasked_secret(
                    name=r.name,
                    scope=r.scope,
                    product_id=r.product_id,
                    vault_client=vault_client,
                )
                if sec:
                    info = {
                        "id": r.id,
                        "name": r.name,
                        "type": r.type,
                        "scope": r.scope,
                        "product_id": r.product_id,
                    }
                    return sec, info

        # Fallback check across all credentials (product or system) ordered by product first, then latest created_at
        query = text("""
            SELECT id, name, type, scope, product_id FROM credentials
            WHERE (type = :type OR type = 'git_token' OR type = 'github_token' OR name = :hostname OR name = :type)
            ORDER BY (CASE WHEN scope = 'product' THEN 1 ELSE 2 END), created_at DESC
        """)
        rows = conn.execute(
            query,
            {"type": credential_type, "hostname": hostname or ""},
        ).fetchall()
        for r in rows:
            sec = get_unmasked_secret(
                name=r.name,
                scope=r.scope,
                product_id=r.product_id,
                vault_client=vault_client,
            )
            if sec:
                info = {
                    "id": r.id,
                    "name": r.name,
                    "type": r.type,
                    "scope": r.scope,
                    "product_id": r.product_id,
                }
                return sec, info

    # 2. Fallback direct Vault path checks (for direct mock_vault or standard key names)
    if product_id:
        for key in (hostname, credential_type, "git_token", "github_token"):
            if key:
                sec = get_unmasked_secret(
                    name=key, scope="product", product_id=product_id, vault_client=vault_client
                )
                if sec:
                    info = {
                        "id": "direct_vault",
                        "name": key,
                        "type": credential_type,
                        "scope": "product",
                        "product_id": product_id,
                    }
                    return sec, info

    for key in (hostname, credential_type, "git_token", "github_token"):
        if key:
            sec = get_unmasked_secret(
                name=key, scope="system", vault_client=vault_client
            )
            if sec:
                info = {
                    "id": "direct_vault",
                    "name": key,
                    "type": credential_type,
                    "scope": "system",
                    "product_id": None,
                }
                return sec, info

    return None, None


def get_unmasked_secret_by_type(
    credential_type: str,
    hostname: str | None = None,
    product_id: str | None = None,
    vault_client: OpenBaoClient | None = None,
) -> str | None:
    sec, _ = get_unmasked_secret_by_type_info(
        credential_type=credential_type,
        hostname=hostname,
        product_id=product_id,
        vault_client=vault_client,
    )
    return sec


def delete_credential(cred_id: str, vault_client: OpenBaoClient | None = None) -> bool:
    cred = get_credential_by_id(cred_id)
    if not cred:
        return False

    client = vault_client or OpenBaoClient()
    vault_path = _build_vault_path(cred["name"], cred["scope"], cred.get("product_id"))
    client.delete_secret(vault_path)

    with get_db_connection() as conn:
        conn.execute(delete(credentials).where(credentials.c.id == cred_id))
    return True
