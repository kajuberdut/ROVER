"""rover/routes/schedules.py: API routes for managing scheduled scans and viewing execution audit logs."""

import json
import logging

import falcon
import falcon.asgi

from rover import db, permissions

logger = logging.getLogger("rover.routes.schedules")


class ProductSchedulesPageResource:
    @falcon.before(permissions.require_product_read)
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, product_id: str
    ) -> None:
        product = db.get_product(product_id)
        if not product:
            raise falcon.HTTPFound("/?error=product_not_found")

        releases = db.get_product_releases(product_id)
        user = getattr(req.context, "user", None)
        product_role = None
        if user:
            product_role = db.get_user_product_role(user["sub"], product_id)

        from rover.routes._env import template_env

        template = template_env.get_template("product_schedules.html")
        resp.text = template.render(
            user=user,
            product_role=product_role,
            product=product,
            releases=releases,
            title=f"Schedules - {product['name']}",
        )
        resp.content_type = falcon.MEDIA_HTML


class ProductSchedulesResource:
    @falcon.before(permissions.require_product_read)
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, product_id: str
    ) -> None:
        schedules = db.get_scheduled_scans_for_product(product_id)
        resp.text = json.dumps({"schedules": schedules}, default=str)
        resp.content_type = falcon.MEDIA_JSON

    @falcon.before(permissions.require_product_read_write)
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, product_id: str
    ) -> None:
        user = getattr(req.context, "user", None)
        user_sub = user.get("sub") if user else None

        data = await req.get_media()
        name = data.get("name", "Scheduled Scan")
        cron_expression = data.get("cron_expression", "0 2 * * *")
        release_id = data.get("release_id") or None
        enabled = data.get("enabled", True)

        try:
            schedule_id = db.create_scheduled_scan(
                product_id=product_id,
                name=name,
                cron_expression=cron_expression,
                release_id=release_id,
                enabled=enabled,
                user_sub=user_sub,
            )
            logger.info(
                f"User {user_sub} created scheduled scan '{name}' ({schedule_id}) for product {product_id}"
            )
            resp.status = falcon.HTTP_201
            resp.text = json.dumps(
                {"schedule_id": schedule_id, "message": "Schedule created successfully"}
            )
            resp.content_type = falcon.MEDIA_JSON
        except Exception as exc:
            logger.error(
                f"Failed to create scheduled scan for product {product_id}: {exc}"
            )
            resp.status = falcon.HTTP_400
            resp.text = json.dumps({"error": str(exc)})
            resp.content_type = falcon.MEDIA_JSON


class ScheduleDetailResource:
    @falcon.before(permissions.require_product_read_write)
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, schedule_id: str
    ) -> None:
        schedule = db.get_scheduled_scan(schedule_id)
        if not schedule:
            resp.status = falcon.HTTP_404
            resp.text = json.dumps({"error": "Schedule not found"})
            resp.content_type = falcon.MEDIA_JSON
            return

        action = req.get_param("action") or "toggle"
        user = getattr(req.context, "user", None)
        user_sub = user.get("sub") if user else None

        if action == "toggle":
            new_enabled = not schedule["enabled"]
            db.update_scheduled_scan(schedule_id, enabled=new_enabled)
            logger.info(
                f"User {user_sub} toggled schedule {schedule_id} to enabled={new_enabled}"
            )
            resp.text = json.dumps({"schedule_id": schedule_id, "enabled": new_enabled})
            resp.content_type = falcon.MEDIA_JSON
        elif action == "trigger":
            logger.info(f"User {user_sub} manually triggered schedule {schedule_id}")
            # Temporarily mark next_run_at to past so engine dispatches it
            from datetime import datetime, timezone

            from rover.scheduler import dispatch_due_scheduled_scans

            db.update_scheduled_scan(
                schedule_id, next_run_at=datetime.now(timezone.utc)
            )
            dispatched = dispatch_due_scheduled_scans()

            resp.text = json.dumps(
                {
                    "schedule_id": schedule_id,
                    "dispatched": dispatched,
                    "message": "Triggered scheduled scan",
                }
            )
            resp.content_type = falcon.MEDIA_JSON
        else:
            resp.status = falcon.HTTP_400
            resp.text = json.dumps({"error": f"Invalid action '{action}'"})
            resp.content_type = falcon.MEDIA_JSON

    @falcon.before(permissions.require_product_read_write)
    async def on_delete(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, schedule_id: str
    ) -> None:
        schedule = db.get_scheduled_scan(schedule_id)
        if not schedule:
            resp.status = falcon.HTTP_404
            resp.text = json.dumps({"error": "Schedule not found"})
            resp.content_type = falcon.MEDIA_JSON
            return

        user = getattr(req.context, "user", None)
        user_sub = user.get("sub") if user else None

        db.delete_scheduled_scan(schedule_id)
        logger.info(f"User {user_sub} deleted scheduled scan {schedule_id}")
        resp.text = json.dumps(
            {"schedule_id": schedule_id, "message": "Schedule deleted"}
        )
        resp.content_type = falcon.MEDIA_JSON


class ScheduleLogsResource:
    @falcon.before(permissions.require_product_read)
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, schedule_id: str
    ) -> None:
        logs = db.get_schedule_execution_logs(schedule_id)
        for log in logs:
            if log.get("details_json"):
                try:
                    details = json.loads(log["details_json"])
                    job_ids = details.get("enqueued_job_ids") or []
                    if job_ids:
                        log["job_summary"] = db.get_jobs_status_summary(job_ids)
                except Exception as exc:
                    logger.warning(
                        f"Failed to summarize enqueued job status for log {log.get('id')}: {exc}"
                    )
        resp.text = json.dumps({"logs": logs}, default=str)
        resp.content_type = falcon.MEDIA_JSON
