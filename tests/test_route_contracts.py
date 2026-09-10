"""tests/test_route_contracts.py: Full-stack contract and integration tests.

Verifies:
1. Every URL and action endpoint referenced in HTML templates matches a mounted Falcon route.
2. Every interactive action endpoint supports dual response contracts (JSON for AJAX vs HTTP 302 for HTML forms).
3. Invalid or missing payloads yield clean HTTP 400/403 JSON error messages.
"""

import re
from pathlib import Path

import pytest
from falcon import testing
from sqlalchemy import create_engine

from rover import db
from rover.db import connection, schema
from rover.routes import create_app


@pytest.fixture(autouse=True)
def sqlite_test_db() -> None:
    test_engine = create_engine("sqlite:///:memory:")
    connection.engine = test_engine
    schema.metadata.create_all(test_engine)


def get_auth_headers(role: str = "system_admin") -> dict[str, str]:
    from rover.auth import COOKIE_NAME, cookie_serializer

    session_data = {
        "sub": "user_admin_123",
        "email": "admin@rover.local",
        "name": "Test Admin",
        "role": role,
        "product_ids": [],
    }
    cookie_val = cookie_serializer.dumps(session_data)
    return {"Cookie": f"{COOKIE_NAME}={cookie_val}"}


def test_template_urls_match_mounted_routes() -> None:
    """Scan all Jinja2 HTML templates for form actions and JS fetch/actionUrls,

    asserting that every referenced path matches a registered Falcon route.
    """
    app = create_app()
    template_dir = Path(__file__).parent.parent / "src" / "rover" / "templates"

    discovered_paths = set()

    for html_file in template_dir.glob("*.html"):
        content = html_file.read_text()

        # Pre-process JS string concatenations and template placeholders
        # e.g., '/admin/invites/' + inviteId + '/revoke' -> '/admin/invites/dummy_id/revoke'
        content = re.sub(
            r"['\"]\s*\+\s*[a-zA-Z0-9_.]+\s*\+\s*['\"]", "dummy_id", content
        )
        content = re.sub(r"['\"]\s*\+\s*[a-zA-Z0-9_.]+", "dummy_id", content)
        content = re.sub(r"\$\{[a-zA-Z0-9_.]+\}", "dummy_id", content)
        content = re.sub(r"\{\{[^}]+\}\}", "dummy_id", content)

        # HTML form actions
        for m in re.finditer(r'action=["\'](/[^"\']+)["\']', content):
            discovered_paths.add(m.group(1))

        # JS actionUrl / fetch literals
        for m in re.finditer(r'(?:actionUrl:\s*|fetch\()["\'](/[^"\']+)["\']', content):
            discovered_paths.add(m.group(1))

    normalized_paths = set()
    for raw_path in discovered_paths:
        clean = raw_path.split("?")[0]
        clean = re.sub(r"//+", "/", clean)
        if clean.endswith("/") and len(clean) > 1:
            clean = clean.rstrip("/")
        normalized_paths.add(clean)

    unmatched = []
    for path in sorted(normalized_paths):
        if path.startswith("/static") or path.startswith("/favicon"):
            continue

        route_found = False
        for method in ("POST", "GET"):
            result = app._router.find(path, req=None)  # type: ignore[attr-defined]
            if result and result[0]:
                route_found = True
                break

        if not route_found:
            unmatched.append(path)

    assert not unmatched, f"Templates reference unmounted routes: {unmatched}"


def test_api_token_routes_dual_contracts() -> None:
    app = create_app()
    client = testing.TestClient(app)
    headers = get_auth_headers("system_admin")

    # 1. Create Token
    form_headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        **headers,
    }
    ajax_resp = client.simulate_post(
        "/settings/tokens/create",
        headers=form_headers,
        body="token_name=TestToken&token_permission=read",
    )
    assert ajax_resp.status_code == 200
    assert ajax_resp.json.get("ok") is True
    assert "new_token" in ajax_resp.json

    html_headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        **headers,
    }
    html_resp = client.simulate_post(
        "/settings/tokens/create",
        headers=html_headers,
        body="token_name=TestToken2&token_permission=write",
    )
    assert html_resp.status_code == 302
    assert "/settings/tokens?new_token=" in html_resp.headers["location"]

    # Invalid token parameters -> 400
    bad_resp = client.simulate_post(
        "/settings/tokens/create",
        headers=form_headers,
        body="token_name=&token_permission=invalid",
    )
    assert bad_resp.status_code == 400

    # 2. Revoke Token
    _, token_id = db.create_api_token("user_admin_123", "RevokeMe", "read")
    ajax_revoke = client.simulate_post(
        f"/settings/tokens/{token_id}/revoke",
        headers={"Accept": "application/json", **headers},
    )
    assert ajax_revoke.status_code == 200
    assert ajax_revoke.json == {"ok": True}

    _, token_id2 = db.create_api_token("user_admin_123", "RevokeMe2", "read")
    html_revoke = client.simulate_post(
        f"/settings/tokens/{token_id2}/revoke",
        headers=headers,
    )
    assert html_revoke.status_code == 302
    assert html_revoke.headers["location"] == "/settings/tokens"


def test_credential_vault_routes_dual_contracts() -> None:
    app = create_app()
    client = testing.TestClient(app)
    headers = get_auth_headers("system_admin")

    body = "name=pat-test&type=git_token&scope=system&secret_value=ghp_12345"
    form_headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        **headers,
    }
    ajax_add = client.simulate_post(
        "/admin/credentials",
        headers=form_headers,
        body=body,
    )
    assert ajax_add.status_code == 200
    assert ajax_add.json == {"ok": True}

    html_add = client.simulate_post(
        "/admin/credentials",
        headers={"Content-Type": "application/x-www-form-urlencoded", **headers},
        body=body,
    )
    assert html_add.status_code == 302
    assert html_add.headers["location"] == "/admin/credentials"

    creds = db.get_credentials()
    assert len(creds) > 0
    cred_id = creds[0]["id"]

    ajax_del = client.simulate_post(
        f"/admin/credentials/{cred_id}/delete",
        headers={"Accept": "application/json", **headers},
    )
    assert ajax_del.status_code == 200
    assert ajax_del.json == {"ok": True}


def test_product_and_release_routes_dual_contracts() -> None:
    app = create_app()
    client = testing.TestClient(app)
    headers = get_auth_headers("system_admin")

    form_headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        **headers,
    }

    # 1. Create Product
    prod_body = "product_name=Contract+Test+Prod&product_description=Desc"
    ajax_prod = client.simulate_post(
        "/products",
        headers=form_headers,
        body=prod_body,
    )
    assert ajax_prod.status_code == 200
    assert ajax_prod.json == {"ok": True}

    prods = db.get_all_products()
    prod_id = prods[0]["id"]

    # 2. Create Release
    rel_body = f"product_id={prod_id}&release_name=v1.0.0&release_version=1.0.0"
    ajax_rel = client.simulate_post(
        "/releases",
        headers=form_headers,
        body=rel_body,
    )
    assert ajax_rel.status_code == 200
    assert ajax_rel.json == {"ok": True}

    releases = db.get_product_releases(prod_id)
    rel_id = releases[0]["id"]

    # 3. Mark EOL
    ajax_eol = client.simulate_post(
        f"/releases/{rel_id}/eol",
        headers=form_headers,
        body="action=mark_eol",
    )
    assert ajax_eol.status_code == 200
    assert ajax_eol.json == {"ok": True}

    # 4. Delete Release
    ajax_rel_del = client.simulate_post(
        f"/releases/{rel_id}/delete",
        headers={"Accept": "application/json", **headers},
    )
    assert ajax_rel_del.status_code == 200
    assert ajax_rel_del.json.get("ok") is True
    assert ajax_rel_del.json.get("redirectUrl") == f"/products/{prod_id}"

    # 5. Delete Product
    ajax_prod_del = client.simulate_post(
        f"/products/{prod_id}/delete",
        headers={"Accept": "application/json", **headers},
    )
    assert ajax_prod_del.status_code == 200
    assert ajax_prod_del.json == {"ok": True, "redirectUrl": "/"}


def test_user_management_and_invites_contracts() -> None:
    app = create_app()
    client = testing.TestClient(app)
    headers = get_auth_headers("system_admin")

    form_headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        **headers,
    }

    # Missing sub -> 400
    bad_user = client.simulate_post(
        "/admin/users",
        headers=form_headers,
        body="action=set_role&role=admin",
    )
    assert bad_user.status_code == 400
    assert bad_user.json == {"error": "Missing sub"}

    # Set Role -> 200
    db.upsert_user("target_sub_1", email="target@rover.local", name="Target")
    role_resp = client.simulate_post(
        "/admin/users",
        headers=form_headers,
        body="action=set_role&sub=target_sub_1&role=system_admin",
    )
    assert role_resp.status_code == 200
    assert role_resp.json == {"ok": True}
