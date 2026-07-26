"""rover/routes/admin.py: System-admin routes: config editor and user management."""

import logging

import falcon
import falcon.asgi

from rover import config, db, permissions
from rover.routes._env import template_env

logger = logging.getLogger(__name__)


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
        users = db.get_all_users()
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
            db.set_user_role(sub, role)

        resp.media = {"ok": True}


class AdminNotificationsResource:
    """Admin-only notification queue UI."""

    @falcon.before(permissions.require_system_admin)
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        active_notifications = db.get_active_admin_notifications()
        all_notifications = db.get_all_admin_notifications(limit=100)
        template = template_env.get_template("admin_notifications.html")
        resp.text = template.render(
            user=getattr(req.context, "user", None),
            title="System Notifications",
            active_notifications=active_notifications,
            all_notifications=all_notifications,
        )
        resp.content_type = falcon.MEDIA_HTML

    @falcon.before(permissions.require_system_admin)
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        try:
            form = await req.get_media()
        except Exception as e:
            logger.warning(f"Failed to parse media in notification dismiss: {e}")
            form = {}

        action = form.get("action") if isinstance(form, dict) else None
        notification_id = (
            form.get("notification_id") if isinstance(form, dict) else None
        )

        if action == "dismiss" and notification_id:
            db.dismiss_admin_notification(notification_id)
            resp.media = {"ok": True}
        elif action == "restore" and notification_id:
            db.restore_admin_notification(notification_id)
            resp.media = {"ok": True}
        else:
            resp.status = falcon.HTTP_400
            resp.media = {"error": "Invalid action or notification_id"}
