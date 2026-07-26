"""rover/routes/products.py: Product management routes."""

import falcon
import falcon.asgi

from rover import db, permissions
from rover.routes._env import template_env


class ProductResource:
    @falcon.before(permissions.require_product_admin)
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        form = await req.get_media()
        name = form.get("product_name")
        description = form.get("product_description", "")
        if name:
            db.add_product(name, description)
        referer = req.get_header("Referer", default="/")
        raise falcon.HTTPFound(referer)


class ProductDashboardResource:
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, product_id: str
    ) -> None:
        product = db.get_product(product_id)
        if not product:
            raise falcon.HTTPFound("/?error=product_not_found")

        releases = db.get_product_releases(product_id)
        product_role = None
        user = getattr(req.context, "user", None)
        if user:
            product_role = db.get_user_product_role(user["sub"], product_id)

        template = template_env.get_template("product_dashboard.html")
        resp.text = template.render(
            user=user,
            product_role=product_role,
            title=f"Product: {product['name']}",
            product=product,
            releases=releases,
            db=db,
        )
        resp.content_type = falcon.MEDIA_HTML


class ProductDeleteResource:
    @falcon.before(permissions.require_system_admin)
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, product_id: str
    ) -> None:
        db.delete_product(product_id)
        raise falcon.HTTPFound("/")


class ProductPermissionsResource:
    @falcon.before(permissions.require_product_admin)
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, product_id: str
    ) -> None:
        product = db.get_product(product_id)
        if not product:
            raise falcon.HTTPFound("/?error=product_not_found")

        all_users = db.get_all_users()
        product_users = db.get_product_users(product_id)

        user_roles = {u["sub"]: u["product_role"] for u in product_users}
        for u in all_users:
            u["product_role"] = user_roles.get(u["sub"], "none")

        template = template_env.get_template("product_permissions.html")
        resp.text = template.render(
            user=getattr(req.context, "user", None),
            title=f"Permissions: {product['name']}",
            product=product,
            all_users=all_users,
        )
        resp.content_type = falcon.MEDIA_HTML

    @falcon.before(permissions.require_product_admin)
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, product_id: str
    ) -> None:
        form = await req.get_media()
        sub = form.get("sub")
        role = form.get("role")

        if not sub or not role:
            raise falcon.HTTPBadRequest()

        if role == "none":
            db.remove_product_user(sub, product_id)
        else:
            db.set_product_user_role(sub, product_id, role)

        resp.media = {"status": "ok"}
