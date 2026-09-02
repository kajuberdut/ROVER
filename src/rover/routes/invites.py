"""src/rover/routes/invites.py — User Invitation Redemption Route."""

import logging
from datetime import datetime, timezone

import falcon
import falcon.asgi

from rover import config, db
from rover.routes._env import template_env

logger = logging.getLogger(__name__)


class AcceptInviteResource:
    """Public & Authenticated route for redeeming user invitation tokens."""

    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        cfg = config.load_config()
        if not cfg.features.allow_user_invites:
            template = template_env.get_template("accept_invite.html")
            resp.text = template.render(
                user=getattr(req.context, "user", None),
                title="Accept Invitation",
                error="User invitations are currently disabled on this system.",
                valid=False,
            )
            resp.content_type = falcon.MEDIA_HTML
            return

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
                user["role"] = updated_invite["role"]
                from rover.auth import COOKIE_NAME, cookie_serializer

                session_token = cookie_serializer.dumps(user)
                resp.set_cookie(
                    COOKIE_NAME,
                    session_token,
                    secure=False,
                    http_only=True,
                    path="/",
                    max_age=86400,
                )

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
        """Handle invite redemption and account creation."""
        cfg = config.load_config()
        if not cfg.features.allow_user_invites:
            resp.status = falcon.HTTP_403
            resp.media = {
                "error": "User invitations are currently disabled on this system."
            }
            return

        form = await req.get_media()
        token = form.get("token")
        if not token:
            resp.status = falcon.HTTP_400
            resp.media = {"error": "Missing token"}
            return

        invite = db.get_user_invite_by_token(token)
        if not invite or invite.get("status") != "pending":
            resp.status = falcon.HTTP_400
            resp.media = {"error": "Invalid or expired invitation token."}
            return

        action = form.get("action")
        if action == "register":
            username = form.get("username", "").strip()
            password = form.get("password", "").strip()
            display_name = form.get("display_name", "").strip() or username.title()

            if not username or not password:
                resp.status = falcon.HTTP_400
                resp.media = {"error": "Username and password are required."}
                return

            if len(password) < 8:
                resp.status = falcon.HTTP_400
                resp.media = {"error": "Password must be at least 8 characters long."}
                return

            email = (
                invite.get("email") or form.get("email") or f"{username}@rover.local"
            )

            try:
                from rover.auth import COOKIE_NAME, add_authelia_user, cookie_serializer

                # 1. Register in Authelia's user database
                add_authelia_user(
                    username=username,
                    email=email,
                    password=password,
                    display_name=display_name,
                )

                # 2. Upsert user in ROVER database
                db_user = db.upsert_user(sub=username, email=email, name=display_name)

                # 3. Redeem invitation token
                updated_invite = db.accept_user_invite(token, username)
                if not updated_invite:
                    resp.status = falcon.HTTP_400
                    resp.media = {"error": "Failed to accept invite or token expired."}
                    return

                # 4. Issue ROVER session cookie
                user_data = {
                    "sub": db_user["sub"],
                    "email": db_user["email"],
                    "name": db_user["name"],
                    "role": updated_invite["role"],
                    "product_ids": db.get_user_product_ids(db_user["sub"]),
                }
                session_token = cookie_serializer.dumps(user_data)
                resp.set_cookie(
                    COOKIE_NAME,
                    session_token,
                    secure=False,
                    http_only=True,
                    path="/",
                    max_age=86400,
                )
                resp.media = {
                    "ok": True,
                    "role": updated_invite["role"],
                    "user": user_data,
                }
                return
            except Exception as e:
                logger.error(f"Failed to register user via invite token: {e}")
                resp.status = falcon.HTTP_500
                resp.media = {"error": f"Failed to create account: {e}"}
                return

        user = getattr(req.context, "user", None)
        if not user or not user.get("sub"):
            raise falcon.HTTPUnauthorized()

        updated_invite = db.accept_user_invite(token, user["sub"])
        if updated_invite:
            user["role"] = updated_invite["role"]
            from rover.auth import COOKIE_NAME, cookie_serializer

            session_token = cookie_serializer.dumps(user)
            resp.set_cookie(
                COOKIE_NAME,
                session_token,
                secure=False,
                http_only=True,
                path="/",
                max_age=86400,
            )
            resp.media = {"ok": True, "role": updated_invite["role"]}
        else:
            resp.status = falcon.HTTP_400
            resp.media = {"error": "Failed to accept invite or invite expired"}
