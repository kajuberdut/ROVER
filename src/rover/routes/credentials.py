"""src/rover/routes/credentials.py — Credential Vault administration routes."""

import falcon
import falcon.asgi

from rover import db, permissions
from rover.routes._env import template_env


class AdminCredentialsResource:
    @falcon.before(permissions.require_system_admin)
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        credentials_list = db.get_credentials()
        products_list = db.get_all_products()

        template = template_env.get_template("credentials.html")
        resp.text = template.render(
            user=getattr(req.context, "user", None),
            title="Credential Vault — ROVER Admin",
            credentials=credentials_list,
            products=products_list,
        )
        resp.content_type = falcon.MEDIA_HTML

    @falcon.before(permissions.require_system_admin)
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        form = await req.get_media()
        name = (form.get("name") or "").strip()
        credential_type = (form.get("type") or "").strip()
        scope = (form.get("scope") or "system").strip()
        product_id = form.get("product_id") or None
        secret_value = form.get("secret_value") or ""
        description = form.get("description") or None

        if name and credential_type and secret_value:
            db.add_credential(
                name=name,
                credential_type=credential_type,
                scope=scope,
                secret_value=secret_value,
                product_id=product_id if scope == "product" else None,
                description=description,
            )

        raise falcon.HTTPFound("/admin/credentials")


class AdminCredentialDeleteResource:
    @falcon.before(permissions.require_system_admin)
    async def on_post(
        self,
        req: falcon.asgi.Request,
        resp: falcon.asgi.Response,
        credential_id: str,
    ) -> None:
        db.delete_credential(credential_id)
        raise falcon.HTTPFound("/admin/credentials")
