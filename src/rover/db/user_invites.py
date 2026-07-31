"""src/rover/db/user_invites.py — User Invitation Data Access Layer."""

import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select, update

from rover.db.connection import get_db_connection
from rover.db.schema import user_invites, users

logger = logging.getLogger(__name__)


def create_user_invite(
    email: str | None,
    role: str,
    invited_by_sub: str,
    expires_in_days: int = 7,
) -> dict[str, Any]:
    """Creates a new pending user invitation."""
    if role not in ("viewer", "system_admin"):
        raise ValueError(f"Invalid role for invite: {role!r}")

    invite_id = str(uuid.uuid4())
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=expires_in_days)
    email_clean = email.strip() if email and email.strip() else None

    with get_db_connection() as conn:
        conn.execute(
            user_invites.insert().values(
                id=invite_id,
                email=email_clean,
                role=role,
                token=token,
                invited_by_sub=invited_by_sub,
                status="pending",
                expires_at=expires_at,
                created_at=now,
            )
        )
        row = conn.execute(
            select(user_invites).where(user_invites.c.id == invite_id)
        ).fetchone()
        invite_dict = dict(row._mapping) if row else {}
        if invite_dict.get("expires_at") and isinstance(
            invite_dict["expires_at"], datetime
        ):
            invite_dict["expires_at"] = invite_dict["expires_at"].isoformat()
        if invite_dict.get("created_at") and isinstance(
            invite_dict["created_at"], datetime
        ):
            invite_dict["created_at"] = invite_dict["created_at"].isoformat()
        return invite_dict


def get_user_invite_by_id(invite_id: str) -> dict[str, Any] | None:
    """Fetches an invite by ID."""
    with get_db_connection() as conn:
        row = conn.execute(
            select(user_invites).where(user_invites.c.id == invite_id)
        ).fetchone()
        if not row:
            return None
        res = dict(row._mapping)
        if res.get("expires_at") and isinstance(res["expires_at"], datetime):
            res["expires_at"] = res["expires_at"].isoformat()
        if res.get("created_at") and isinstance(res["created_at"], datetime):
            res["created_at"] = res["created_at"].isoformat()
        return res


def get_user_invite_by_token(token: str) -> dict[str, Any] | None:
    """Fetches an invite by secret token."""
    with get_db_connection() as conn:
        row = conn.execute(
            select(user_invites).where(user_invites.c.token == token)
        ).fetchone()
        if not row:
            return None
        res = dict(row._mapping)
        return res


def get_pending_user_invites() -> list[dict[str, Any]]:
    """Lists all active pending invitations that have not expired."""
    now = datetime.now(timezone.utc)
    with get_db_connection() as conn:
        rows = conn.execute(
            select(user_invites)
            .where(
                user_invites.c.status == "pending",
                user_invites.c.expires_at > now,
            )
            .order_by(user_invites.c.created_at.desc())
        ).fetchall()
        invites = []
        for row in rows:
            res = dict(row._mapping)
            if res.get("expires_at") and isinstance(res["expires_at"], datetime):
                res["expires_at"] = res["expires_at"].isoformat()
            if res.get("created_at") and isinstance(res["created_at"], datetime):
                res["created_at"] = res["created_at"].isoformat()
            invites.append(res)
        return invites


def get_all_user_invites(limit: int = 100) -> list[dict[str, Any]]:
    """Lists all user invitations up to limit."""
    with get_db_connection() as conn:
        rows = conn.execute(
            select(user_invites).order_by(user_invites.c.created_at.desc()).limit(limit)
        ).fetchall()
        invites = []
        for row in rows:
            res = dict(row._mapping)
            if res.get("expires_at") and isinstance(res["expires_at"], datetime):
                res["expires_at"] = res["expires_at"].isoformat()
            if res.get("created_at") and isinstance(res["created_at"], datetime):
                res["created_at"] = res["created_at"].isoformat()
            invites.append(res)
        return invites


def revoke_user_invite(invite_id: str) -> bool:
    """Revokes a pending invitation."""
    with get_db_connection() as conn:
        result = conn.execute(
            update(user_invites)
            .where(user_invites.c.id == invite_id, user_invites.c.status == "pending")
            .values(status="revoked")
        )
        return result.rowcount > 0


def accept_user_invite(token: str, accepting_user_sub: str) -> dict[str, Any] | None:
    """Redeems an invitation token, assigning the granted role to the accepting user."""
    with get_db_connection() as conn:
        row = conn.execute(
            select(user_invites).where(user_invites.c.token == token)
        ).fetchone()
        if not row:
            return None
        invite = dict(row._mapping)

        # Check status and expiration
        now = datetime.now(timezone.utc)
        expires_at = invite.get("expires_at")
        if isinstance(expires_at, str):
            try:
                expires_at = datetime.fromisoformat(expires_at)
            except ValueError:
                expires_at = None

        if invite["status"] != "pending":
            logger.warning(
                f"Invite {token} cannot be accepted: status is {invite['status']}"
            )
            return None

        if expires_at and expires_at < now:
            conn.execute(
                update(user_invites)
                .where(user_invites.c.token == token)
                .values(status="expired")
            )
            logger.warning(f"Invite {token} has expired")
            return None

        # Assign role to user in users table
        conn.execute(
            update(users)
            .where(users.c.sub == accepting_user_sub)
            .values(role=invite["role"])
        )

        # Mark invite as accepted
        conn.execute(
            update(user_invites)
            .where(user_invites.c.token == token)
            .values(
                status="accepted",
                accepted_at=now,
                accepted_by_sub=accepting_user_sub,
            )
        )

        updated_row = conn.execute(
            select(user_invites).where(user_invites.c.token == token)
        ).fetchone()
        return dict(updated_row._mapping) if updated_row else invite
