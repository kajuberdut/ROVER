import uuid
import secrets
import hashlib
from typing import Any
from sqlalchemy import select, insert, delete, update
from sqlalchemy.sql import func
from rover.db.connection import get_db_connection
from rover.db.schema import api_tokens

def create_api_token(user_sub: str, name: str, permission: str) -> tuple[str, str]:
    if permission not in ("read", "write"):
        raise ValueError("Invalid permission. Must be 'read' or 'write'.")
    
    prefix = "rover_r_" if permission == "read" else "rover_w_"
    cleartext_token = prefix + secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(cleartext_token.encode("utf-8")).hexdigest()
    token_id = str(uuid.uuid4())
    
    with get_db_connection() as conn:
        conn.execute(
            insert(api_tokens).values(
                id=token_id,
                user_sub=user_sub,
                name=name,
                token_hash=token_hash,
                permission=permission
            )
        )
    return cleartext_token, token_id

def get_user_api_tokens(user_sub: str) -> list[dict[str, Any]]:
    with get_db_connection() as conn:
        rows = conn.execute(
            select(
                api_tokens.c.id, api_tokens.c.user_sub, api_tokens.c.name,
                api_tokens.c.permission, api_tokens.c.created_at, api_tokens.c.last_used_at
            )
            .where(api_tokens.c.user_sub == user_sub)
            .order_by(api_tokens.c.created_at.desc())
        ).fetchall()
        return [dict(row._mapping) for row in rows]

def revoke_api_token(token_id: str, user_sub: str) -> None:
    with get_db_connection() as conn:
        conn.execute(
            delete(api_tokens)
            .where(api_tokens.c.id == token_id, api_tokens.c.user_sub == user_sub)
        )

def verify_api_token(token_string: str) -> dict[str, Any] | None:
    if not (token_string.startswith("ro_") or token_string.startswith("rover_r_") or token_string.startswith("rover_w_")):
        return None
        
    token_hash = hashlib.sha256(token_string.encode("utf-8")).hexdigest()
    
    with get_db_connection() as conn:
        row = conn.execute(select(api_tokens).where(api_tokens.c.token_hash == token_hash)).fetchone()
        if row:
            conn.execute(
                update(api_tokens)
                .where(api_tokens.c.id == row.id)
                .values(last_used_at=func.current_timestamp())
            )
            return dict(row._mapping)
    return None
