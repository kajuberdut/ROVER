"""tests/test_notification_routes.py — Unit tests for Notification Settings UI and Test Ping API."""

from unittest.mock import MagicMock, patch

import pytest
from falcon import testing
from test_notifications import MockVaultClient

from rover import db
from rover.routes import create_app


@pytest.fixture
def client() -> testing.TestClient:
    app = create_app()
    return testing.TestClient(app)


def get_auth_headers(role: str = "system_admin") -> dict[str, str]:
    from rover.auth import COOKIE_NAME, cookie_serializer

    session_data = {
        "sub": "test-user-sub",
        "email": "test@rover.local",
        "name": "Test Admin",
        "role": role,
        "product_ids": [],
    }
    cookie_val = cookie_serializer.dumps(session_data)
    return {"Cookie": f"{COOKIE_NAME}={cookie_val}"}


def test_user_and_product_notification_pages(client: testing.TestClient) -> None:
    mock_vault = MockVaultClient()
    prod = db.add_product(name="UI Test Product", description="Test")

    # Seed destination & rule
    dest = db.add_notification_destination(
        name="UI Webhook",
        destination_type="webhook",
        scope="product",
        product_id=prod,
        config_dict={"url": "https://example.com/webhook"},
        vault_client=mock_vault,  # type: ignore
    )
    db.add_notification_rule(
        destination_id=dest["id"],
        event_type="scan.completed",
        scope="product",
        product_id=prod,
    )

    headers = get_auth_headers("system_admin")

    # 1. User Notifications Settings Page
    res_user = client.simulate_get("/user/settings/notifications", headers=headers)
    assert res_user.status_code == 200
    assert "Personal Notification Subscriptions" in res_user.text

    # 2. Product Notifications Settings Page
    res_prod = client.simulate_get(
        f"/products/{prod}/settings/notifications", headers=headers
    )
    assert res_prod.status_code == 200
    assert "Notifications: UI Test Product" in res_prod.text
    assert "UI Webhook" in res_prod.text


def test_notification_destination_test_ping(client: testing.TestClient) -> None:
    mock_vault = MockVaultClient()
    dest = db.add_notification_destination(
        name="Ping Target",
        destination_type="webhook",
        scope="system",
        config_dict={"url": "https://example.com/ping"},
        secret_value="ping-secret",  # noqa: S106
        vault_client=mock_vault,  # type: ignore
    )

    headers = get_auth_headers("system_admin")

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        res = client.simulate_post(
            f"/api/notifications/destinations/{dest['id']}/test", headers=headers
        )
        assert res.status_code == 200
        assert res.json["status"] == "ok"
        assert res.json["delivered"] is True


def test_admin_destinations_page_and_permissions(client: testing.TestClient) -> None:
    headers_admin = get_auth_headers("system_admin")
    headers_user = get_auth_headers("developer")

    # System admin can view destinations page
    res_admin = client.simulate_get(
        "/admin/notifications/destinations", headers=headers_admin
    )
    assert res_admin.status_code == 200
    assert "System Notification Destinations" in res_admin.text

    # Non-admin cannot view admin destinations page
    res_user = client.simulate_get(
        "/admin/notifications/destinations", headers=headers_user
    )
    assert res_user.status_code == 403

    # Non-admin cannot create destination
    res_create = client.simulate_post(
        "/api/notifications/destinations",
        body="name=BadDest&type=webhook&webhook_url=http://example.com",
        headers={"Content-Type": "application/x-www-form-urlencoded", **headers_user},
    )
    assert res_create.status_code == 403
