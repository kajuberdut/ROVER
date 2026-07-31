"""
permissions.py; Falcon hook functions and context helpers for RBAC.

Usage (as a Falcon before-hook):
    @falcon.before(require_system_admin)
    async def on_post(self, req, resp): ...

    @falcon.before(require_product_admin)
    async def on_post(self, req, resp, product_id): ...
"""

from typing import Any

import falcon

from rover import db


def _get_user(req: falcon.asgi.Request) -> dict[str, Any]:
    user: dict[str, Any] | None = getattr(req.context, "user", None)
    if not user:
        raise falcon.HTTPUnauthorized(description="Authentication required.")

    if user.get("api_token_permission") == "read" and req.method not in (
        "GET",
        "HEAD",
        "OPTIONS",
    ):
        raise falcon.HTTPForbidden(description="API token has read-only permission.")

    return user


async def require_system_admin(
    req: falcon.asgi.Request, resp: falcon.asgi.Response, _resource: Any, params: Any
) -> None:
    """Allow only system admins."""
    user = _get_user(req)
    if user.get("role") != "system_admin":
        raise falcon.HTTPForbidden(description="System Admin access required.")


def _resolve_product_id(req: falcon.asgi.Request, params: Any) -> str | None:
    # 1. Check direct product_id
    product_id = params.get("product_id")
    if not product_id:
        body = getattr(req.context, "_body", None) or {}
        product_id = body.get("product_id")

    if product_id:
        return str(product_id)

    # 2. Check via release_id
    release_id = params.get("release_id")
    if not release_id:
        body = getattr(req.context, "_body", None) or {}
        release_id = body.get("release_id")

    if release_id:
        release = db.get_release(release_id)
        if release and release.get("product_id"):
            return str(release["product_id"])

    # 3. Check via release_asset_id
    release_asset_id = params.get("release_asset_id")
    if not release_asset_id:
        body = getattr(req.context, "_body", None) or {}
        release_asset_id = body.get("release_asset_id")

    if release_asset_id:
        release_asset = db.get_release_asset(release_asset_id)
        if release_asset:
            release = db.get_release(release_asset["release_id"])
            if release and release.get("product_id"):
                return str(release["product_id"])

    # 4. Check via schedule_id
    schedule_id = params.get("schedule_id")
    if not schedule_id:
        body = getattr(req.context, "_body", None) or {}
        schedule_id = body.get("schedule_id")

    if schedule_id:
        schedule = db.get_scheduled_scan(schedule_id)
        if schedule and schedule.get("product_id"):
            return str(schedule["product_id"])

    return None


def _check_product_role(
    req: falcon.asgi.Request, params: Any, allowed_roles: set[str]
) -> None:
    user = _get_user(req)
    if user.get("role") == "system_admin":
        return

    product_id = _resolve_product_id(req, params)
    if not product_id:
        # No resolvable product context, allow the request to proceed so the handler
        # can reject it due to missing parameters.
        return

    product_role = db.get_user_product_role(user["sub"], product_id)
    if not product_role:
        # If no explicit product ACL restrictions exist for this product, allow default read access
        product_users = db.get_product_users(product_id)
        if not product_users and "read" in allowed_roles:
            return

    if not product_role or product_role not in allowed_roles:
        raise falcon.HTTPForbidden(description="Insufficient product permissions.")


async def require_product_admin(
    req: falcon.asgi.Request, resp: falcon.asgi.Response, _resource: Any, params: Any
) -> None:
    _check_product_role(req, params, {"admin"})


async def require_product_read_write(
    req: falcon.asgi.Request, resp: falcon.asgi.Response, _resource: Any, params: Any
) -> None:
    _check_product_role(req, params, {"admin", "read_write"})


async def require_product_read(
    req: falcon.asgi.Request, resp: falcon.asgi.Response, _resource: Any, params: Any
) -> None:
    _check_product_role(req, params, {"admin", "read_write", "read"})


async def require_api_write_token(
    req: falcon.asgi.Request, resp: falcon.asgi.Response, _resource: Any, params: Any
) -> None:
    """Explicitly require authentication via an API token that has write permissions."""
    user = _get_user(req)

    # Check if this user was authenticated via an API token
    if "api_token_permission" not in user:
        raise falcon.HTTPForbidden(
            description="This endpoint requires a valid API token."
        )

    if user["api_token_permission"] != "write":  # noqa: S105
        raise falcon.HTTPForbidden(
            description="This endpoint requires an API token with write permissions."
        )
