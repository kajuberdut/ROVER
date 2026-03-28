"""
permissions.py — Falcon hook functions and context helpers for RBAC.

Usage (as a Falcon before-hook):
    @falcon.before(require_admin)
    async def on_post(self, req, resp): ...

    @falcon.before(require_product_owner_or_admin, product_id_param="product_id")
    async def on_post(self, req, resp, product_id): ...
"""

import falcon

from rover import scan_queue

VALID_ROLES = ("viewer", "product_owner", "admin")


def _get_user(req: falcon.asgi.Request) -> dict:
    user = getattr(req.context, "user", None)
    if not user:
        raise falcon.HTTPUnauthorized(description="Authentication required.")
    return user


async def require_admin(
    req: falcon.asgi.Request, resp: falcon.asgi.Response, resource, params
) -> None:
    """Allow only admins."""
    user = _get_user(req)
    if user.get("role") != "admin":
        raise falcon.HTTPForbidden(description="Admin access required.")


async def require_product_owner_or_admin(
    req: falcon.asgi.Request,
    resp: falcon.asgi.Response,
    resource,
    params,
    product_id_param: str = "product_id",
) -> None:
    """
    Allow admins unconditionally.
    Allow product_owners only if they own the product identified by
    the product_id_param URI template variable (or POST body field).
    """
    user = _get_user(req)
    role = user.get("role", "viewer")

    if role == "admin":
        return

    if role != "product_owner":
        raise falcon.HTTPForbidden(
            description="Product owner or admin access required."
        )

    # Resolve product_id: prefer URI param, fall back to POST body
    product_id = params.get(product_id_param)
    if not product_id:
        body = getattr(req.context, "_body", None) or {}
        product_id = body.get("product_id") or body.get(product_id_param)

    if not product_id:
        # No product_id in context — allow the request and let the handler
        # perform ownership verification after reading the body.
        return

    if not scan_queue.user_owns_product(user["sub"], product_id):
        raise falcon.HTTPForbidden(
            description="You do not have owner access to this product."
        )


async def require_product_owner_or_admin_for_release(
    req: falcon.asgi.Request,
    resp: falcon.asgi.Response,
    resource,
    params,
) -> None:
    """
    For release-level operations: look up the release's parent product and
    check ownership against that.
    """
    user = _get_user(req)
    role = user.get("role", "viewer")

    if role == "admin":
        return

    if role != "product_owner":
        raise falcon.HTTPForbidden(
            description="Product owner or admin access required."
        )

    release_id = params.get("release_id")
    if not release_id:
        return  # Let handler reject with a more specific message

    release = scan_queue.get_release(release_id)
    if not release:
        raise falcon.HTTPNotFound()

    if not scan_queue.user_owns_product(user["sub"], release["product_id"]):
        raise falcon.HTTPForbidden(
            description="You do not have owner access to this release's product."
        )


async def require_product_owner_or_admin_for_release_asset(
    req: falcon.asgi.Request,
    resp: falcon.asgi.Response,
    resource,
    params,
) -> None:
    """
    For release-asset-level operations: look up the parent release's product and
    check ownership against that.
    """
    user = _get_user(req)
    role = user.get("role", "viewer")

    if role == "admin":
        return

    if role != "product_owner":
        raise falcon.HTTPForbidden(
            description="Product owner or admin access required."
        )

    release_asset_id = params.get("release_asset_id")
    if not release_asset_id:
        return  # Let handler reject with a more specific message

    release_asset = scan_queue.get_release_asset(release_asset_id)
    if not release_asset:
        raise falcon.HTTPNotFound()

    release = scan_queue.get_release(release_asset["release_id"])
    if not release:
        raise falcon.HTTPNotFound()

    if not scan_queue.user_owns_product(user["sub"], release["product_id"]):
        raise falcon.HTTPForbidden(
            description="You do not have owner access to this release asset's product."
        )
