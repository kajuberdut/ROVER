"""tests/test_user_invites.py — Unit tests for User Invitation Workflow."""

from datetime import datetime, timedelta, timezone

import pytest

from rover.db import connection, schema
from rover.db.user_invites import (
    accept_user_invite,
    create_user_invite,
    get_pending_user_invites,
    get_user_invite_by_token,
    revoke_user_invite,
)


@pytest.fixture
def test_user():
    sub = "user-inviter-123"
    with connection.get_db_connection() as conn:
        conn.execute(
            schema.users.insert().values(
                sub=sub,
                email="admin@company.com",
                name="Admin Inviter",
                role="system_admin",
            )
        )
    yield sub
    with connection.get_db_connection() as conn:
        conn.execute(schema.user_invites.delete())
        conn.execute(schema.users.delete().where(schema.users.c.sub == sub))


def test_create_user_invite(test_user):
    invite = create_user_invite(
        email="newuser@company.com",
        role="viewer",
        invited_by_sub=test_user,
        expires_in_days=7,
    )
    assert invite["id"] is not None
    assert invite["email"] == "newuser@company.com"
    assert invite["role"] == "viewer"
    assert invite["status"] == "pending"
    assert len(invite["token"]) > 20

    fetched = get_user_invite_by_token(invite["token"])
    assert fetched is not None
    assert fetched["id"] == invite["id"]


def test_get_pending_user_invites(test_user):
    inv1 = create_user_invite("p1@co.com", "viewer", test_user)
    inv2 = create_user_invite("p2@co.com", "system_admin", test_user)

    pending = get_pending_user_invites()
    pending_ids = [p["id"] for p in pending]
    assert inv1["id"] in pending_ids
    assert inv2["id"] in pending_ids


def test_revoke_user_invite(test_user):
    inv = create_user_invite("revoke@co.com", "viewer", test_user)
    revoked = revoke_user_invite(inv["id"])
    assert revoked is True

    fetched = get_user_invite_by_token(inv["token"])
    assert fetched["status"] == "revoked"

    pending = get_pending_user_invites()
    pending_ids = [p["id"] for p in pending]
    assert inv["id"] not in pending_ids


def test_accept_user_invite(test_user):
    recipient_sub = "user-invitee-456"
    with connection.get_db_connection() as conn:
        conn.execute(
            schema.users.insert().values(
                sub=recipient_sub,
                email="newuser@company.com",
                name="New User",
                role="viewer",
            )
        )

    try:
        inv = create_user_invite("newuser@company.com", "system_admin", test_user)
        accepted = accept_user_invite(inv["token"], recipient_sub)
        assert accepted is not None
        assert accepted["status"] == "accepted"

        with connection.get_db_connection() as conn:
            user_row = conn.execute(
                schema.users.select().where(schema.users.c.sub == recipient_sub)
            ).fetchone()
            assert user_row is not None
            assert user_row._mapping["role"] == "system_admin"
    finally:
        with connection.get_db_connection() as conn:
            conn.execute(schema.user_invites.delete())
            conn.execute(
                schema.users.delete().where(schema.users.c.sub == recipient_sub)
            )


def test_expired_user_invite(test_user):
    inv = create_user_invite("expired@co.com", "viewer", test_user)

    # Force expiration in DB
    past_time = datetime.now(timezone.utc) - timedelta(days=1)
    with connection.get_db_connection() as conn:
        conn.execute(
            schema.user_invites.update()
            .where(schema.user_invites.c.id == inv["id"])
            .values(expires_at=past_time)
        )

    accepted = accept_user_invite(inv["token"], test_user)
    assert accepted is None

    fetched = get_user_invite_by_token(inv["token"])
    assert fetched["status"] == "expired"
