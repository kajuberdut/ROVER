"""rover/routes/admin.py: System-admin routes: config editor and user management."""

import logging

import falcon
import falcon.asgi

from rover import config, db, permissions
from rover.routes._env import template_env

logger = logging.getLogger(__name__)


class AdminRedirectResource:
    """Redirects /admin to /config."""

    @falcon.before(permissions.require_system_admin)
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        raise falcon.HTTPFound("/config")


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
        cfg = config.load_config()
        users = db.get_all_users()
        pending_invites = db.get_pending_user_invites()
        default_email_dest = db.get_default_smtp_destination()

        # Compute invite links for pending invites
        host_header = req.forwarded_host or req.netloc
        base_url = f"{req.scheme}://{host_header}"
        for inv in pending_invites:
            inv["invite_link"] = f"{base_url}/accept-invite?token={inv['token']}"

        template = template_env.get_template("admin_users.html")
        resp.text = template.render(
            user=getattr(req.context, "user", None),
            title="User Management",
            users=users,
            pending_invites=pending_invites,
            default_email_dest=default_email_dest,
            allow_user_invites=cfg.features.allow_user_invites,
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
        elif action == "revoke_api_tokens":
            count = db.revoke_all_user_api_tokens(sub)
            resp.media = {"ok": True, "count": count}
            return

        resp.media = {"ok": True}


class AdminInvitesCreateResource:
    """Resource for creating user invitations."""

    @falcon.before(permissions.require_system_admin)
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        cfg = config.load_config()
        if not cfg.features.allow_user_invites:
            resp.status = falcon.HTTP_403
            resp.media = {
                "error": "User invitations are currently disabled on this system."
            }
            return

        user = getattr(req.context, "user", None)
        if not user:
            raise falcon.HTTPUnauthorized()

        form = await req.get_media()
        email = form.get("email")
        role = form.get("role", "viewer")
        send_email = form.get("send_email") in (True, "true", "1", "on")

        if role not in ("viewer", "system_admin"):
            resp.status = falcon.HTTP_400
            resp.media = {"error": "Invalid role"}
            return

        invite = db.create_user_invite(
            email=email,
            role=role,
            invited_by_sub=user["sub"],
            expires_in_days=7,
        )

        host_header = req.forwarded_host or req.netloc
        invite_link = (
            f"{req.scheme}://{host_header}/accept-invite?token={invite['token']}"
        )
        invite["invite_link"] = invite_link

        default_dest = db.get_default_smtp_destination()
        email_sent = False
        if send_email and email and default_dest:
            from rover.notifications.engine import deliver_notification

            vault_secret = None
            if default_dest.get("vault_secret_path"):
                vault_secret = db.get_destination_unmasked_secret(default_dest["id"])

            payload = {
                "event_type": "user.invited",
                "title": "You've been invited to R.O.V.E.R.",
                "severity": "INFO",
                "message": f"You have been invited to join the R.O.V.E.R. Security Platform as a {role.replace('_', ' ').title()}.\n\nClick the link below to accept your invitation:\n{invite_link}\n\nThis invitation expires in 7 days.",
                "product_name": "R.O.V.E.R. System",
                "recipient_emails": [email.strip()],
                "to_email": email.strip(),
            }
            try:
                email_sent = deliver_notification(
                    default_dest, payload, vault_secret=vault_secret
                )
            except Exception as e:
                logger.error(f"Failed to deliver invite email to {email}: {e}")
                email_sent = False

        resp.media = {
            "ok": True,
            "invite": invite,
            "invite_link": invite_link,
            "email_sent": email_sent,
        }


class AdminInvitesRevokeResource:
    """Resource for revoking pending invitations."""

    @falcon.before(permissions.require_system_admin)
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, invite_id: str
    ) -> None:
        cfg = config.load_config()
        if not cfg.features.allow_user_invites:
            resp.status = falcon.HTTP_403
            resp.media = {
                "error": "User invitations are currently disabled on this system."
            }
            return

        success = db.revoke_user_invite(invite_id)
        if success:
            resp.media = {"ok": True}
        else:
            resp.status = falcon.HTTP_404
            resp.media = {"error": "Invite not found or already processed"}


class AdminInvitesResendResource:
    """Resource for resending invite emails."""

    @falcon.before(permissions.require_system_admin)
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, invite_id: str
    ) -> None:
        cfg = config.load_config()
        if not cfg.features.allow_user_invites:
            resp.status = falcon.HTTP_403
            resp.media = {
                "error": "User invitations are currently disabled on this system."
            }
            return

        invite = db.get_user_invite_by_id(invite_id)
        if not invite or invite["status"] != "pending":
            resp.status = falcon.HTTP_404
            resp.media = {"error": "Pending invite not found"}
            return

        if not invite.get("email"):
            resp.status = falcon.HTTP_400
            resp.media = {"error": "Invite has no email address assigned"}
            return

        default_dest = db.get_default_smtp_destination()
        if not default_dest:
            resp.status = falcon.HTTP_400
            resp.media = {"error": "No default system email gateway configured"}
            return

        host_header = req.forwarded_host or req.netloc
        invite_link = (
            f"{req.scheme}://{host_header}/accept-invite?token={invite['token']}"
        )

        from rover.notifications.engine import deliver_notification

        vault_secret = None
        if default_dest.get("vault_secret_path"):
            vault_secret = db.get_destination_unmasked_secret(default_dest["id"])

        payload = {
            "event_type": "user.invited",
            "title": "You've been invited to R.O.V.E.R. (Reminder)",
            "severity": "INFO",
            "message": f"Reminder: You have been invited to join R.O.V.E.R. as a {invite['role'].replace('_', ' ').title()}.\n\nClick the link below to accept your invitation:\n{invite_link}",
            "product_name": "R.O.V.E.R. System",
            "recipient_emails": [invite["email"]],
            "to_email": invite["email"],
        }
        sent = deliver_notification(default_dest, payload, vault_secret=vault_secret)
        resp.media = {"ok": True, "email_sent": sent}


class AdminAlertsResource:
    """Admin-only system alerts queue UI."""

    @falcon.before(permissions.require_system_admin)
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        active_notifications = db.get_active_admin_notifications()
        all_notifications = db.get_all_admin_notifications(limit=100)
        template = template_env.get_template("admin_alerts.html")
        resp.text = template.render(
            user=getattr(req.context, "user", None),
            title="System Admin Alerts",
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


class AdminDestinationsResource:
    """Admin-only notification destinations management UI."""

    @falcon.before(permissions.require_system_admin)
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        destinations = db.get_notification_destinations()
        template = template_env.get_template("admin_destinations.html")
        resp.text = template.render(
            user=getattr(req.context, "user", None),
            title="Notification Destinations Management",
            destinations=destinations,
        )
        resp.content_type = falcon.MEDIA_HTML
