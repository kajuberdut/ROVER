"""rover/routes/dashboard.py — Top-level dashboard and queue-table routes."""

import falcon
import falcon.asgi

from rover import scan_queue
from rover.routes._env import template_env


class DashboardResource:
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        jobs = scan_queue.get_all_jobs()
        repositories = scan_queue.get_all_repositories()
        images = scan_queue.get_all_images()
        products = scan_queue.get_all_products()
        releases = scan_queue.get_all_releases()
        major_components = scan_queue.get_all_major_components()
        template = template_env.get_template("dashboard.html")
        resp.text = template.render(
            user=getattr(req.context, "user", None),
            title="R.O.V.E.R Dashboard",
            jobs=jobs,
            repositories=repositories,
            images=images,
            products=products,
            releases=releases,
            major_components=major_components,
            scan_queue=scan_queue,
        )
        resp.content_type = falcon.MEDIA_HTML


class QueueTableResource:
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        jobs = scan_queue.get_all_jobs()
        template = template_env.get_template("queue_table.html")
        resp.text = template.render(jobs=jobs)
        resp.content_type = falcon.MEDIA_HTML
