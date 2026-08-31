"""rover/routes/notifications.py: Notification settings and destination API routes."""

from typing import Any

import falcon
import falcon.asgi

from rover import db, permissions
from rover.email_tokens import send_verification_email
from rover.notifications.transports import deliver_notification
from rover.routes._env import template_env


class UserNotificationsPageResource:
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        user = getattr(req.context, "user", None)
        if not user:
            raise falcon.HTTPUnauthorized()

        user_sub = user["sub"]
        all_destinations = db.get_notification_destinations()
        default_email_dest = db.get_default_smtp_destination()
        is_admin = user.get("role") == "system_admin"

        if is_admin:
            available_destinations = all_destinations
        else:
            # Standard users subscribe to email alerts via email gateways (SMTP / AWS SES)
            available_destinations = [
                d for d in all_destinations if d.get("type") in ("smtp", "aws_ses")
            ]

        destination_names = {d["id"]: d["name"] for d in all_destinations}
        rules = db.get_notification_rules(scope="user", user_sub=user_sub)
        all_users = db.get_all_users()

        template = template_env.get_template("settings_notifications.html")
        resp.text = template.render(
            user=user,
            title="Personal Notification Subscriptions",
            scope="user",
            available_destinations=available_destinations,
            default_email_dest=default_email_dest,
            rules=rules,
            destination_names=destination_names,
            all_users=all_users,
        )
        resp.content_type = falcon.MEDIA_HTML


class ProductNotificationsPageResource:
    @falcon.before(permissions.require_product_admin)
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, product_id: str
    ) -> None:
        product = db.get_product(product_id)
        if not product:
            raise falcon.HTTPFound("/?error=product_not_found")

        user = getattr(req.context, "user", None)
        available_destinations = db.get_notification_destinations()
        default_email_dest = db.get_default_smtp_destination()
        destination_names = {d["id"]: d["name"] for d in available_destinations}
        rules = db.get_notification_rules(scope="product", product_id=product_id)
        all_users = db.get_all_users()

        template = template_env.get_template("settings_notifications.html")
        resp.text = template.render(
            user=user,
            title=f"Notifications: {product['name']}",
            scope="product",
            product=product,
            available_destinations=available_destinations,
            default_email_dest=default_email_dest,
            rules=rules,
            destination_names=destination_names,
            all_users=all_users,
        )
        resp.content_type = falcon.MEDIA_HTML


class AdminDestinationsResource:
    @falcon.before(permissions.require_system_admin)
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        user = getattr(req.context, "user", None)
        destinations = db.get_notification_destinations()
        template = template_env.get_template("admin_destinations.html")
        resp.text = template.render(
            user=user,
            title="Notification Destinations Management",
            destinations=destinations,
        )
        resp.content_type = falcon.MEDIA_HTML


class NotificationDestinationCreateResource:
    @falcon.before(permissions.require_system_admin)
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        user = getattr(req.context, "user", None)
        if not user:
            raise falcon.HTTPUnauthorized()

        form = await req.get_media()
        name = form.get("name")
        dest_type = form.get("type")
        scope = form.get("scope", "system")
        product_id = form.get("product_id")

        if not name or not dest_type:
            raise falcon.HTTPBadRequest(
                description="Destination name and type are required."
            )

        config_dict = {}
        secret_val = None

        if dest_type == "webhook":
            config_dict["url"] = form.get("webhook_url")
            secret_val = form.get("webhook_secret")
        elif dest_type == "slack":
            config_dict["webhook_url"] = form.get("slack_url")
        elif dest_type == "smtp":
            config_dict = {
                "smtp_host": form.get("smtp_host"),
                "smtp_port": form.get("smtp_port") or 587,
                "smtp_username": form.get("smtp_username"),
                "from_email": form.get("smtp_from_email"),
                "encryption": form.get("smtp_encryption", "starttls"),
            }
            secret_val = {"smtp_password": form.get("smtp_password")}
        elif dest_type == "aws_ses":
            config_dict = {
                "region": form.get("aws_region") or "us-east-1",
                "aws_access_key_id": form.get("aws_access_key_id"),
                "from_email": form.get("aws_from_email"),
            }
            secret_val = {"aws_secret_access_key": form.get("aws_secret_access_key")}

        is_default = form.get("is_default") in ("true", "1", True, "on")

        db.add_notification_destination(
            name=name,
            destination_type=dest_type,
            scope=scope,
            config_dict=config_dict,
            secret_value=secret_val,
            user_sub=user["sub"] if scope == "user" else None,
            product_id=product_id if scope == "product" else None,
            is_default=is_default,
        )

        referer = req.get_header("Referer", default="/admin/notifications/destinations")
        raise falcon.HTTPFound(referer)


class NotificationDestinationDeleteResource:
    @falcon.before(permissions.require_system_admin)
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, dest_id: str
    ) -> None:
        user = getattr(req.context, "user", None)
        if not user:
            raise falcon.HTTPUnauthorized()

        db.delete_notification_destination(dest_id)
        referer = req.get_header("Referer", default="/admin/notifications/destinations")
        raise falcon.HTTPFound(referer)


class NotificationDestinationUpdateResource:
    @falcon.before(permissions.require_system_admin)
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, dest_id: str
    ) -> None:
        user = getattr(req.context, "user", None)
        if not user:
            raise falcon.HTTPUnauthorized()

        dest = db.get_notification_destination_by_id(dest_id)
        if not dest:
            raise falcon.HTTPNotFound()

        form = await req.get_media()
        name = form.get("name") or dest.get("name")
        dest_type = dest.get("type")

        existing_config = dest.get("config", {})
        config_dict = dict(existing_config)
        secret_val: str | dict[str, Any] | None = None

        if dest_type == "webhook":
            config_dict["url"] = form.get("webhook_url") or existing_config.get("url")
            sec = form.get("webhook_secret")
            if sec:
                secret_val = sec
        elif dest_type == "slack":
            config_dict["webhook_url"] = form.get("slack_url") or existing_config.get(
                "webhook_url"
            )
        elif dest_type == "smtp":
            config_dict["smtp_host"] = form.get("smtp_host") or existing_config.get(
                "smtp_host"
            )
            config_dict["smtp_port"] = (
                form.get("smtp_port") or existing_config.get("smtp_port") or 587
            )
            config_dict["smtp_username"] = form.get(
                "smtp_username"
            ) or existing_config.get("smtp_username")
            config_dict["from_email"] = form.get(
                "smtp_from_email"
            ) or existing_config.get("from_email")
            config_dict["encryption"] = form.get(
                "smtp_encryption"
            ) or existing_config.get("encryption", "starttls")
            pass_val = form.get("smtp_password")
            if pass_val:
                secret_val = {"smtp_password": pass_val}
        elif dest_type == "aws_ses":
            config_dict["region"] = form.get("aws_region") or existing_config.get(
                "region", "us-east-1"
            )
            config_dict["aws_access_key_id"] = form.get(
                "aws_access_key_id"
            ) or existing_config.get("aws_access_key_id")
            config_dict["from_email"] = form.get(
                "aws_from_email"
            ) or existing_config.get("from_email")
            sec_key = form.get("aws_secret_access_key")
            if sec_key:
                secret_val = {"aws_secret_access_key": sec_key}

        is_default = form.get("is_default") in ("true", "1", True, "on")

        db.update_notification_destination(
            dest_id=dest_id,
            name=name,
            config_dict=config_dict,
            secret_value=secret_val,
            is_default=is_default,
        )

        referer = req.get_header("Referer", default="/admin/notifications/destinations")
        raise falcon.HTTPFound(referer)


class NotificationDestinationSetDefaultResource:
    @falcon.before(permissions.require_system_admin)
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, dest_id: str
    ) -> None:
        user = getattr(req.context, "user", None)
        if not user:
            raise falcon.HTTPUnauthorized()

        db.set_default_smtp_destination(dest_id)
        referer = req.get_header("Referer", default="/admin/notifications/destinations")
        raise falcon.HTTPFound(referer)


class NotificationRuleCreateResource:
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        user = getattr(req.context, "user", None)
        if not user:
            raise falcon.HTTPUnauthorized()

        form = await req.get_media()
        destination_id = form.get("destination_id")
        if not destination_id:
            default_dest = db.get_default_smtp_destination()
            if default_dest:
                destination_id = default_dest["id"]

        event_type = form.get("event_type")
        scope = form.get("scope", "user")
        product_id = form.get("product_id")
        min_severity = (
            form.get("min_severity", "ALL")
            if event_type == "vulnerability.found"
            else "ALL"
        )
        eol_warning_days = (
            form.get("eol_warning_days") if event_type == "eol.warning" else None
        )
        eol_warning_days_int = int(eol_warning_days) if eol_warning_days else None

        if not destination_id or not event_type:
            raise falcon.HTTPBadRequest(
                description="Destination and event_type are required."
            )

        is_admin_user = (user.get("role") == "system_admin") or (
            product_id and db.get_user_product_role(user["sub"], product_id) == "admin"
        )

        if is_admin_user:
            recipient_user_subs_raw = (
                form.getall("recipient_user_subs")
                if hasattr(form, "getall")
                else form.get("recipient_user_subs")
            )
            if isinstance(recipient_user_subs_raw, str):
                recipient_user_subs = [recipient_user_subs_raw]
            elif isinstance(recipient_user_subs_raw, list):
                recipient_user_subs = [str(s) for s in recipient_user_subs_raw if s]
            else:
                recipient_user_subs = []

            custom_emails_raw = form.get("custom_recipient_emails", "")
            custom_emails = [
                e.strip() for e in str(custom_emails_raw).split(",") if e.strip()
            ]
            base_url = f"{req.scheme}://{req.forwarded_host or req.host}"
            for email_addr in custom_emails:
                target_user = db.ensure_email_only_user(email_addr, is_verified=False)
                if not target_user.get("is_verified"):
                    send_verification_email(
                        email_addr,
                        target_type="user",
                        target_id=target_user["sub"],
                        base_url=base_url,
                    )
        else:
            recipient_user_subs = [user["sub"]]
            custom_emails = []

        db.add_notification_rule(
            destination_id=destination_id,
            event_type=event_type,
            scope=scope,
            min_severity=min_severity,
            eol_warning_days=eol_warning_days_int,
            user_sub=user["sub"] if scope == "user" else None,
            product_id=product_id if scope == "product" else None,
            recipient_user_subs=recipient_user_subs,
            recipient_emails=custom_emails,
        )

        referer = req.get_header("Referer", default="/user/settings/notifications")
        raise falcon.HTTPFound(referer)


class NotificationRuleDeleteResource:
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, rule_id: str
    ) -> None:
        user = getattr(req.context, "user", None)
        if not user:
            raise falcon.HTTPUnauthorized()

        db.delete_notification_rule(rule_id)
        referer = req.get_header("Referer", default="/user/settings/notifications")
        raise falcon.HTTPFound(referer)


class NotificationDestinationTestResource:
    """Test Ping endpoint for notification destinations."""

    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, dest_id: str
    ) -> None:
        user = getattr(req.context, "user", None)
        if not user:
            raise falcon.HTTPUnauthorized()

        dest = db.get_notification_destination_by_id(dest_id)
        if not dest:
            resp.media = {
                "status": "error",
                "error": "Destination not found",
                "delivered": False,
            }
            resp.status = falcon.HTTP_404
            return

        vault_secret = None
        if dest.get("vault_secret_path"):
            vault_secret = db.get_destination_unmasked_secret(dest_id)

        user_email = (
            user.get("email") if user and user.get("email") else "admin@rover.local"
        )
        test_payload = {
            "event_type": "notification.test",
            "title": "Test Ping Notification",
            "severity": "INFO",
            "message": f"This is a test ping notification from ROVER for destination '{dest['name']}'.",
            "product_name": "ROVER Test System",
            "recipient_emails": [user_email],
            "to_email": user_email,
        }

        try:
            delivered = deliver_notification(
                dest, test_payload, vault_secret=vault_secret
            )
            if delivered:
                db.log_notification_attempt(
                    destination_id=dest_id,
                    event_type="notification.test",
                    status="delivered",
                    http_status_code=200,
                    payload_dict=test_payload,
                )
                resp.media = {"status": "ok", "delivered": True}
            else:
                err_msg = "Transport delivery failed. Check target URL, host reachability (e.g. host.docker.internal for local listeners), or secret credentials."
                db.log_notification_attempt(
                    destination_id=dest_id,
                    event_type="notification.test",
                    status="failed",
                    http_status_code=500,
                    error_message=err_msg,
                    payload_dict=test_payload,
                )
                resp.media = {
                    "status": "error",
                    "error": err_msg,
                    "delivered": False,
                }
        except Exception as e:
            db.log_notification_attempt(
                destination_id=dest_id,
                event_type="notification.test",
                status="failed",
                http_status_code=500,
                error_message=str(e),
                payload_dict=test_payload,
            )
            resp.media = {"status": "error", "error": str(e), "delivered": False}
