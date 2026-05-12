"""rover/routes/admin.py — System-admin routes: config editor and user management."""

import falcon
import falcon.asgi

from rover import config, permissions, scan_queue
from rover.routes._env import template_env


class ConfigResource:
    @falcon.before(permissions.require_system_admin)
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        raw_toml = config.read_raw_config()
        template = template_env.get_template("config.html")
        resp.text = template.render(
            user=getattr(req.context, "user", None),
            title="Configuration",
            raw_toml=raw_toml,
        )
        resp.content_type = falcon.MEDIA_HTML

    @falcon.before(permissions.require_system_admin)
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        form = await req.get_media()
        raw_toml = form.get("raw_toml", "")
        template = template_env.get_template("config.html")
        try:
            config.save_raw_config(raw_toml)
            saved_toml = config.read_raw_config()
            # Update global settings in memory
            config.settings = config.load_config()
            resp.text = template.render(
                user=getattr(req.context, "user", None),
                title="Configuration",
                raw_toml=saved_toml,
                success=True,
            )
        except Exception as e:
            resp.text = template.render(
                user=getattr(req.context, "user", None),
                title="Configuration",
                raw_toml=raw_toml,
                error=str(e),
            )
            resp.status = falcon.HTTP_400
        resp.content_type = falcon.MEDIA_HTML


class AdminUsersResource:
    """Admin-only user management UI."""

    @falcon.before(permissions.require_system_admin)
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        users = scan_queue.get_all_users()
        template = template_env.get_template("admin_users.html")
        resp.text = template.render(
            user=getattr(req.context, "user", None),
            title="User Management",
            users=users,
        )
        resp.content_type = falcon.MEDIA_HTML

    @falcon.before(permissions.require_system_admin)
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        """Handle role changes."""
        form = await req.get_media()
        action = form.get("action")
        sub = form.get("sub")

        if not sub:
            resp.status = falcon.HTTP_400
            resp.media = {"error": "Missing sub"}
            return

        if action == "set_role":
            role = form.get("role")
            scan_queue.set_user_role(sub, role)

        resp.media = {"ok": True}
