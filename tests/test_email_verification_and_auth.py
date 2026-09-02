"""tests/test_email_verification_and_auth.py — Tests for Email Verification, Password Reset & Email-Only Users."""

import uuid

import pytest
from falcon import testing

from rover import db
from rover.db import connection, schema
from rover.email_tokens import (
    generate_email_verification_token,
    generate_password_reset_token,
    verify_email_verification_token,
    verify_password_reset_token,
)
from rover.notifications import dispatch_event
from rover.routes import create_app


@pytest.fixture(autouse=True)
def setup_db():
    schema.metadata.create_all(connection.engine)


def test_email_verification_token_lifecycle():
    email = "testuser@example.com"
    token = generate_email_verification_token(
        email, target_type="user", target_id="sub_123"
    )
    assert isinstance(token, str)

    payload = verify_email_verification_token(token)
    assert payload is not None
    assert payload["email"] == email
    assert payload["type"] == "user"
    assert payload["id"] == "sub_123"

    # Bad token
    assert verify_email_verification_token("invalid.token.here") is None


def test_password_reset_token_lifecycle():
    sub = f"user_reset_{uuid.uuid4().hex[:8]}"
    email = f"{sub}@example.com"
    db.upsert_user(sub=sub, email=email, name="Reset Test User")
    db.update_user_password(sub, "old_hash_123")

    token = generate_password_reset_token(email)
    assert isinstance(token, str)

    result = verify_password_reset_token(token)
    assert result == email

    # Simulate password change
    db.update_user_password(sub, "new_hash_456")

    # Attempting to reuse the token must return None
    assert verify_password_reset_token(token) is None

    # Bad token
    assert verify_password_reset_token("invalid.token") is None


def test_confirm_email_route():
    app = create_app()
    client = testing.TestClient(app)

    sub = f"user_test_{uuid.uuid4().hex[:8]}"
    email = f"{sub}@example.com"
    db.upsert_user(sub=sub, email=email, name="Verification Test User")

    token = generate_email_verification_token(email, target_type="user", target_id=sub)

    resp = client.simulate_get(f"/confirm-email?token={token}")
    assert resp.status_code == 200
    assert "Email Address Verified!" in resp.text

    db_user = db.get_user(sub)
    assert db_user is not None
    assert db_user.get("is_verified") is True


def test_forgot_and_reset_password_routes():
    app = create_app()
    client = testing.TestClient(app)

    # 1. GET /forgot-password
    resp = client.simulate_get("/forgot-password")
    assert resp.status_code == 200
    assert "Forgot Password" in resp.text

    # 2. POST /forgot-password
    resp = client.simulate_post(
        "/forgot-password",
        body="email=user@example.com",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 200
    assert "recovery link has been sent" in resp.text

    # 3. GET /reset-password with token
    token = generate_password_reset_token("user@example.com")
    resp = client.simulate_get(f"/reset-password?token={token}")
    assert resp.status_code == 200
    assert "Reset Password" in resp.text


def test_email_only_role_restrictions():
    app = create_app()
    client = testing.TestClient(app)

    sub = f"email_only_{uuid.uuid4().hex[:8]}"
    email = f"{sub}@example.com"
    db.upsert_user(sub=sub, email=email, name="Email Only User", role="email_only")

    # Issue cookie session for email_only user
    from rover.auth import COOKIE_NAME, cookie_serializer

    session_data = {
        "sub": sub,
        "email": email,
        "name": "Email Only User",
        "role": "email_only",
        "product_ids": [],
    }
    cookie_val = cookie_serializer.dumps(session_data)

    # Attempting to access dashboard should redirect to /user/subscriptions
    resp = client.simulate_get("/", cookies={COOKIE_NAME: cookie_val})
    assert resp.status_code == 302
    assert resp.headers.get("location") == "/user/subscriptions"

    # Accessing /user/subscriptions is allowed
    resp = client.simulate_get("/user/subscriptions", cookies={COOKIE_NAME: cookie_val})
    assert resp.status_code == 200
    assert "My Subscriptions" in resp.text


def test_magic_access_token_subscription_flow():
    app = create_app()
    client = testing.TestClient(app)

    # 1. Unauthenticated request to /user/subscriptions renders magic link access page
    resp = client.simulate_get("/user/subscriptions")
    assert resp.status_code == 200
    assert "Access Notification Subscriptions" in resp.text

    # 2. Request magic link via POST
    magic_email = f"magic_{uuid.uuid4().hex[:8]}@rover.local"
    resp = client.simulate_post(
        "/user/subscriptions",
        body=f"email={magic_email}",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 200
    assert "If a subscription exists" in resp.text

    # 3. Redeem magic token via GET /user/subscriptions?token=...
    from rover.email_tokens import generate_magic_access_token

    token = generate_magic_access_token(magic_email)

    resp = client.simulate_get(f"/user/subscriptions?token={token}")
    assert resp.status_code == 200
    assert "My Subscriptions" in resp.text
    # Verify session cookie was set
    cookie_header = resp.headers.get("set-cookie")
    assert cookie_header is not None
    assert "rover_session=" in cookie_header


def test_notification_engine_requires_email_verification():
    sub = "user_test_unverified"
    dest = db.add_notification_destination(
        name="Unverified User Email",
        destination_type="smtp",
        scope="user",
        user_sub=sub,
        config_dict={"smtp_host": "localhost", "to_email": "unverified@example.com"},
        is_system=False,
        is_default=False,
        is_verified=False,
    )

    rule = db.add_notification_rule(
        destination_id=dest["id"],
        event_type="vulnerability.found",
        min_severity="HIGH",
        scope="user",
        user_sub=sub,
    )

    results = dispatch_event(
        event_type="vulnerability.found",
        payload={"vulnerability": {"severity": "HIGH", "title": "Test CVE"}},
        severity="HIGH",
        user_sub=sub,
    )
    assert len(results) >= 1
    matched = next((r for r in results if r["rule_id"] == rule["id"]), None)
    assert matched is not None
    assert matched["status"] == "skipped_unverified"


def test_custom_recipient_email_auto_provisions_email_only_user():
    app = create_app()
    client = testing.TestClient(app)

    dest = db.add_notification_destination(
        name="System Test SMTP",
        destination_type="smtp",
        scope="system",
        config_dict={"smtp_host": "localhost"},
        is_system=True,
        is_default=True,
    )

    admin_sub = f"admin_{uuid.uuid4().hex[:8]}"
    admin_email = f"{admin_sub}@example.com"
    db.upsert_user(
        sub=admin_sub, email=admin_email, name="Admin User", role="system_admin"
    )

    from rover.auth import COOKIE_NAME, cookie_serializer

    session_data = {
        "sub": admin_sub,
        "email": admin_email,
        "name": "Admin User",
        "role": "system_admin",
        "product_ids": [],
    }
    cookie_val = cookie_serializer.dumps(session_data)

    custom_email = f"recipient_{uuid.uuid4().hex[:8]}@rover.local"

    # Post new rule with custom recipient email
    resp = client.simulate_post(
        "/api/notifications/rules",
        body=f"destination_id={dest['id']}&event_type=vulnerability.found&scope=user&min_severity=ALL&custom_recipient_emails={custom_email}",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        cookies={COOKIE_NAME: cookie_val},
    )
    assert resp.status_code == 302

    # Verify email_only user account was auto-provisioned
    user = db.get_user_by_email(custom_email)
    assert user is not None
    assert user["role"] == "email_only"
    assert user["is_verified"] is False


def test_email_only_user_upgrade_preserves_rules_and_destinations():
    email = f"upgrade_{uuid.uuid4().hex[:8]}@rover.local"
    # 1. Provision email_only user
    user = db.ensure_email_only_user(email, is_verified=True)
    initial_sub = user["sub"]
    assert user["role"] == "email_only"
    assert user["is_verified"] is True

    # 2. Add notification destination & rule for this email_only user
    dest = db.add_notification_destination(
        name="Personal Email",
        destination_type="smtp",
        scope="user",
        user_sub=initial_sub,
        config_dict={"smtp_host": "localhost", "to_email": email},
        is_verified=True,
    )
    rule = db.add_notification_rule(
        destination_id=dest["id"],
        event_type="vulnerability.found",
        scope="user",
        user_sub=initial_sub,
    )

    # 3. User logs in via OIDC or is granted viewer role with new OIDC sub
    oidc_sub = f"oidc_{uuid.uuid4().hex[:8]}"
    upgraded_user = db.upsert_user(
        sub=oidc_sub, email=email, name="Upgraded User", role="viewer"
    )

    # 4. Verify account and references migrated cleanly
    assert upgraded_user["sub"] == oidc_sub
    assert upgraded_user["role"] == "viewer"
    assert upgraded_user["is_verified"] is True

    # Verify notification destinations and rules re-bound to new oidc_sub
    destinations = db.get_notification_destinations(user_sub=oidc_sub)
    rules = db.get_notification_rules(user_sub=oidc_sub)
    assert len(destinations) == 1
    assert destinations[0]["id"] == dest["id"]
    assert len(rules) == 1
    assert rules[0]["id"] == rule["id"]


def test_email_only_unsubscribe_flow():
    app = create_app()
    client = testing.TestClient(app)

    sub = f"unsub_user_{uuid.uuid4().hex[:8]}"
    email = f"{sub}@rover.local"
    db.ensure_email_only_user(email, is_verified=True)

    dest = db.add_notification_destination(
        name="Mailpit",
        destination_type="smtp",
        scope="system",
        config_dict={"smtp_host": "localhost"},
    )
    rule = db.add_notification_rule(
        destination_id=dest["id"],
        event_type="scan.completed",
        scope="system",
        recipient_emails=[email],
    )

    # 1. Verify get_notification_rules returns rule when filtered by user_email
    rules = db.get_notification_rules(user_sub=sub, user_email=email)
    assert len(rules) == 1
    assert rules[0]["id"] == rule["id"]

    # 2. Issue session cookie and POST to unsubscribe endpoint
    from rover.auth import COOKIE_NAME, cookie_serializer

    session_data = {
        "sub": sub,
        "email": email,
        "name": "Unsub User",
        "role": "email_only",
        "product_ids": [],
    }
    cookie_val = cookie_serializer.dumps(session_data)

    resp = client.simulate_post(
        "/user/subscriptions/unsubscribe",
        body=f"rule_id={rule['id']}",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        cookies={COOKIE_NAME: cookie_val},
    )
    assert resp.status_code == 302

    # 3. Verify user is unsubscribed cleanly
    rules_after = db.get_notification_rules(user_sub=sub, user_email=email)
    assert len(rules_after) == 0
