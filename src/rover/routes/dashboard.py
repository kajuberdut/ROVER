"""rover/routes/dashboard.py: Top-level dashboard and queue-table routes."""

import falcon
import falcon.asgi

from rover import config, db
from rover.routes._env import template_env


class DashboardResource:
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        jobs = db.get_all_jobs()
        repositories = db.get_all_repositories()
        images = db.get_all_images()
        products = db.get_all_products()
        releases = db.get_all_releases()
        major_components = db.get_all_major_components()
        credentials = db.get_credentials()
        default_tab = getattr(config.settings.ui, "default_tab", "repo")
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
            credentials=credentials,
            default_tab=default_tab,
            db=db,
        )
        resp.content_type = falcon.MEDIA_HTML


class QueueTableResource:
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        jobs = db.get_all_jobs()
        template = template_env.get_template("queue_table.html")
        resp.text = template.render(jobs=jobs)
        resp.content_type = falcon.MEDIA_HTML


class FaviconResource:
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        resp.status = falcon.HTTP_204
