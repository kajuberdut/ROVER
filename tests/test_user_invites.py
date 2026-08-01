"""tests/test_user_invites.py — Unit tests for User Invitation Workflow."""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from falcon import testing

from rover.db import connection, schema
from rover.db.user_invites import (
    accept_user_invite,
    create_user_invite,
    get_pending_user_invites,
    get_user_invite_by_token,
    revoke_user_invite,
)
from rover.routes import create_app


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


def test_disabled_user_invites_config(test_user):
    inv = create_user_invite("disabled@co.com", "viewer", test_user)

    app = create_app()
    client = testing.TestClient(app)

    from rover.auth import COOKIE_NAME, cookie_serializer

    cookie_val = cookie_serializer.dumps(
        {
            "sub": test_user,
            "email": "admin@company.com",
            "name": "Admin Inviter",
            "role": "system_admin",
            "product_ids": [],
        }
    )
    headers = {"Cookie": f"{COOKIE_NAME}={cookie_val}"}

    with patch("rover.config.load_config") as mock_cfg:
        from rover.config import FeaturesConfig, RoverConfig

        mock_cfg.return_value = RoverConfig(
            features=FeaturesConfig(allow_user_invites=False)
        )

        # Existing invite link redemption should fail when config is disabled
        res_get = client.simulate_get(f"/accept-invite?token={inv['token']}")
        assert res_get.status_code == 200
        assert "User invitations are currently disabled on this system." in res_get.text

        # API creation should return HTTP 403 Forbidden
        res_create = client.simulate_post(
            "/admin/invites/create",
            json={"email": "test@co.com", "role": "viewer"},
            headers=headers,
        )
        assert res_create.status_code == 403
        assert "disabled" in res_create.text


def test_register_user_via_invite(test_user, tmp_path):
    inv = create_user_invite("newcolleague@co.com", "system_admin", test_user)

    app = create_app()
    client = testing.TestClient(app)

    db_yaml = tmp_path / "users_database.yml"
    db_yaml.write_text("users:\n  admin:\n    email: admin@rover.local\n")

    with (
        patch(
            "rover.auth.generate_authelia_argon2_hash",
            return_value="$argon2id$mockhash",
        ),
        patch("rover.auth.add_authelia_user"),
    ):
        res = client.simulate_post(
            "/accept-invite",
            json={
                "token": inv["token"],
                "action": "register",
                "username": "newcolleague",
                "password": "securepassword123",
                "display_name": "New Colleague",
            },
        )
        assert res.status_code == 200
        assert res.json.get("ok") is True
        assert res.json.get("role") == "system_admin"

        # Verify user was upserted into DB
        fetched = get_user_invite_by_token(inv["token"])
        assert fetched["status"] == "accepted"

        # Clean up
        with connection.get_db_connection() as conn:
            conn.execute(
                schema.user_invites.delete().where(
                    schema.user_invites.c.id == inv["id"]
                )
            )
            conn.execute(
                schema.users.delete().where(schema.users.c.sub == "newcolleague")
            )
