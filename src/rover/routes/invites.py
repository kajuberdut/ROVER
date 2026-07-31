"""src/rover/routes/invites.py — User Invitation Redemption Route."""

import logging
from datetime import datetime, timezone

import falcon
import falcon.asgi

from rover import db
from rover.routes._env import template_env

logger = logging.getLogger(__name__)


class AcceptInviteResource:
    """Public & Authenticated route for redeeming user invitation tokens."""

    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        token = req.get_param("token")
        if not token:
            resp.status = falcon.HTTP_400
            template = template_env.get_template("accept_invite.html")
            resp.text = template.render(
                user=getattr(req.context, "user", None),
                title="Accept Invitation",
                error="No invitation token provided.",
                valid=False,
            )
            resp.content_type = falcon.MEDIA_HTML
            return

        invite = db.get_user_invite_by_token(token)
        if not invite:
            template = template_env.get_template("accept_invite.html")
            resp.text = template.render(
                user=getattr(req.context, "user", None),
                title="Accept Invitation",
                error="Invalid or unrecognized invitation token.",
                valid=False,
            )
            resp.content_type = falcon.MEDIA_HTML
            return

        # Check status and expiration
        now = datetime.now(timezone.utc)
        expires_at = invite.get("expires_at")
        if isinstance(expires_at, str):
            try:
                expires_at = datetime.fromisoformat(expires_at)
            except ValueError:
                expires_at = None

        if invite.get("status") != "pending":
            template = template_env.get_template("accept_invite.html")
            resp.text = template.render(
                user=getattr(req.context, "user", None),
                title="Accept Invitation",
                error=f"This invitation has already been {invite.get('status', 'processed')}.",
                valid=False,
                invite=invite,
            )
            resp.content_type = falcon.MEDIA_HTML
            return

        if expires_at and expires_at < now:
            db.revoke_user_invite(invite["id"])
            template = template_env.get_template("accept_invite.html")
            resp.text = template.render(
                user=getattr(req.context, "user", None),
                title="Accept Invitation",
                error="This invitation link has expired.",
                valid=False,
                invite=invite,
            )
            resp.content_type = falcon.MEDIA_HTML
            return

        user = getattr(req.context, "user", None)

        # If user is authenticated, redeem the invite immediately
        redeemed = False
        if user and user.get("sub"):
            updated_invite = db.accept_user_invite(token, user["sub"])
            if updated_invite:
                redeemed = True
                user["role"] = invite["role"]

        template = template_env.get_template("accept_invite.html")
        resp.text = template.render(
            user=user,
            title="Accept Invitation",
            invite=invite,
            valid=True,
            redeemed=redeemed,
            token=token,
        )
        resp.content_type = falcon.MEDIA_HTML

    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        """Handle authenticated POST redemption."""
        user = getattr(req.context, "user", None)
        if not user or not user.get("sub"):
            raise falcon.HTTPUnauthorized()

        form = await req.get_media()
        token = form.get("token")
        if not token:
            resp.status = falcon.HTTP_400
            resp.media = {"error": "Missing token"}
            return

        updated_invite = db.accept_user_invite(token, user["sub"])
        if updated_invite:
            user["role"] = updated_invite["role"]
            resp.media = {"ok": True, "role": updated_invite["role"]}
        else:
            resp.status = falcon.HTTP_400
            resp.media = {"error": "Failed to accept invite or invite expired"}
