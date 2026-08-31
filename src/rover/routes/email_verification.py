"""src/rover/routes/email_verification.py — Email Verification, Password Reset & Email-Only Subscriptions Routes."""

import logging

import falcon
import falcon.asgi

from rover import db
from rover.auth import set_user_session_cookie, update_authelia_user_password
from rover.email_tokens import (
    send_magic_access_email,
    send_password_reset_email,
    send_verification_email,
    verify_email_verification_token,
    verify_magic_access_token,
    verify_password_reset_token,
)
from rover.routes._env import template_env

logger = logging.getLogger(__name__)


class ConfirmEmailResource:
    """Public route for confirming email deliverability via signed token link."""

    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        token = req.get_param("token")
        if not token:
            template = template_env.get_template("confirm_email.html")
            resp.text = template.render(
                user=getattr(req.context, "user", None),
                title="Confirm Email",
                success=False,
                error="No verification token provided.",
            )
            resp.content_type = falcon.MEDIA_HTML
            return

        payload = verify_email_verification_token(token)
        if not payload:
            template = template_env.get_template("confirm_email.html")
            resp.text = template.render(
                user=getattr(req.context, "user", None),
                title="Confirm Email",
                success=False,
                error="Verification link is invalid or has expired (24 hour limit).",
            )
            resp.content_type = falcon.MEDIA_HTML
            return

        email = payload.get("email")
        target_type = payload.get("type", "user")
        target_id = payload.get("id")

        if target_type == "destination" and target_id:
            db.set_destination_verified(target_id, True)
        elif email:
            db.set_user_verified(email, True)
            if target_id:
                db.set_user_verified(target_id, True)

            user_obj = db.get_user_by_email(email) or (
                db.get_user(target_id) if target_id else None
            )
            if user_obj:
                set_user_session_cookie(resp, req, user_obj)

        user = getattr(req.context, "user", None)
        template = template_env.get_template("confirm_email.html")
        resp.text = template.render(
            user=user,
            title="Email Confirmed",
            success=True,
            email=email,
        )
        resp.content_type = falcon.MEDIA_HTML


class ForgotPasswordResource:
    """Public route for requesting password recovery email link."""

    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        email_param = req.get_param("email", default="")
        template = template_env.get_template("forgot_password.html")
        resp.text = template.render(
            user=getattr(req.context, "user", None),
            title="Forgot Password",
            submitted=False,
            email=email_param,
        )
        resp.content_type = falcon.MEDIA_HTML

    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        form = await req.get_media()
        email = str(form.get("email", "")).strip()

        if email:
            db_user = db.get_user_by_email(email) or db.get_user(email)
            if db_user:
                base_url = f"{req.scheme}://{req.forwarded_host or req.host}"
                send_password_reset_email(email, base_url=base_url)

        template = template_env.get_template("forgot_password.html")
        resp.text = template.render(
            user=getattr(req.context, "user", None),
            title="Forgot Password",
            submitted=True,
            email=email,
        )
        resp.content_type = falcon.MEDIA_HTML


class ResetPasswordResource:
    """Public route for choosing a new password via recovery token."""

    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        token = req.get_param("token")
        target_identity = verify_password_reset_token(token) if token else None

        template = template_env.get_template("reset_password.html")
        resp.text = template.render(
            user=getattr(req.context, "user", None),
            title="Reset Password",
            valid=bool(target_identity),
            token=token,
            error=None
            if target_identity
            else "Invalid or expired password reset link.",
        )
        resp.content_type = falcon.MEDIA_HTML

    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        form = await req.get_media()
        token = str(form.get("token", ""))
        new_password = str(form.get("new_password", "")).strip()
        confirm_password = str(form.get("confirm_password", "")).strip()

        target_identity = verify_password_reset_token(token) if token else None
        if not target_identity:
            template = template_env.get_template("reset_password.html")
            resp.text = template.render(
                user=getattr(req.context, "user", None),
                title="Reset Password",
                valid=False,
                error="Invalid or expired reset link. Please request a new recovery link.",
            )
            resp.content_type = falcon.MEDIA_HTML
            return

        if len(new_password) < 8:
            template = template_env.get_template("reset_password.html")
            resp.text = template.render(
                user=getattr(req.context, "user", None),
                title="Reset Password",
                valid=True,
                token=token,
                error="Password must be at least 8 characters long.",
            )
            resp.content_type = falcon.MEDIA_HTML
            return

        if new_password != confirm_password:
            template = template_env.get_template("reset_password.html")
            resp.text = template.render(
                user=getattr(req.context, "user", None),
                title="Reset Password",
                valid=True,
                token=token,
                error="Passwords do not match.",
            )
            resp.content_type = falcon.MEDIA_HTML
            return

        try:
            update_authelia_user_password(target_identity, new_password)
            template = template_env.get_template("reset_password.html")
            resp.text = template.render(
                user=getattr(req.context, "user", None),
                title="Reset Password",
                success=True,
            )
            resp.content_type = falcon.MEDIA_HTML
        except Exception as e:
            logger.error(f"Failed to reset user password: {e}")
            template = template_env.get_template("reset_password.html")
            resp.text = template.render(
                user=getattr(req.context, "user", None),
                title="Reset Password",
                valid=True,
                token=token,
                error=f"Failed to update password: {e}",
            )
            resp.content_type = falcon.MEDIA_HTML


class UserSubscriptionsResource:
    """Self-Service Notification & Unsubscribe Portal for Email-Only and Regular Users."""

    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        token = req.get_param("token")
        if token:
            email_from_token = verify_magic_access_token(token)
            if email_from_token:
                magic_user = db.ensure_email_only_user(
                    email_from_token, is_verified=True
                )
                set_user_session_cookie(resp, req, magic_user)

        user = getattr(req.context, "user", None)
        if not user:
            template = template_env.get_template("access_subscriptions.html")
            resp.text = template.render(
                user=None,
                title="Access Subscriptions",
                submitted=False,
                error="Magic access link is invalid or has expired." if token else None,
            )
            resp.content_type = falcon.MEDIA_HTML
            return

        sub = user.get("sub")
        email = user.get("email") or sub

        db_user = db.get_user(sub) or (db.get_user_by_email(email) if email else None)
        is_verified = bool(db_user.get("is_verified")) if db_user else False

        user_rules = db.get_notification_rules(user_sub=sub)
        user_destinations = db.get_notification_destinations(user_sub=sub)

        template = template_env.get_template("user_subscriptions.html")
        resp.text = template.render(
            user=user,
            title="My Subscriptions",
            db_user=db_user,
            is_verified=is_verified,
            rules=user_rules,
            destinations=user_destinations,
            verified_message=req.get_param("verified") == "true",
            unsubscribed_message=req.get_param("unsubscribed") == "true",
        )
        resp.content_type = falcon.MEDIA_HTML

    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        user = getattr(req.context, "user", None)
        if not user:
            form = await req.get_media()
            email = str(form.get("email", "")).strip()
            if email:
                base_url = f"{req.scheme}://{req.forwarded_host or req.host}"
                send_magic_access_email(email, base_url=base_url)
            template = template_env.get_template("access_subscriptions.html")
            resp.text = template.render(
                user=None,
                title="Access Subscriptions",
                submitted=True,
                email=email,
            )
            resp.content_type = falcon.MEDIA_HTML
            return


class ResendVerificationResource:
    """Dispatches a fresh email verification link to the current user."""

    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        user = req.context.user
        email = user.get("email") or user.get("sub")
        if email and "@" in email:
            base_url = f"{req.scheme}://{req.forwarded_host or req.host}"
            send_verification_email(
                email, target_type="user", target_id=user["sub"], base_url=base_url
            )

        raise falcon.HTTPFound("/user/subscriptions?resent=true")


class UnsubscribeResource:
    """Unsubscribes a user from notification rules/destinations."""

    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        user = req.context.user
        sub = user.get("sub")

        form = await req.get_media()
        rule_id = form.get("rule_id")
        dest_id = form.get("destination_id")
        unsubscribe_all = form.get("all") == "true"

        if rule_id:
            db.delete_notification_rule(rule_id)
        elif dest_id:
            db.delete_notification_destination(dest_id)
        elif unsubscribe_all:
            user_rules = db.get_notification_rules(user_sub=sub)
            for r in user_rules:
                db.delete_notification_rule(r["id"])
            user_dests = db.get_notification_destinations(user_sub=sub)
            for d in user_dests:
                db.delete_notification_destination(d["id"])

        raise falcon.HTTPFound("/user/subscriptions?unsubscribed=true")
