import asyncio
import json
import os

import falcon
import falcon.asgi
import jinja2

from rover import scan_queue, worker

# Configure Jinja2 environment
template_dir = os.path.join(os.path.dirname(__file__), "templates")
template_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir),
    autoescape=jinja2.select_autoescape(["html", "xml"]),
)
template_env.filters["loadjson"] = json.loads


class DashboardResource:
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        jobs = scan_queue.get_all_jobs()
        template = template_env.get_template("dashboard.html")
        resp.text = template.render(title="R.O.V.E.R Dashboard", jobs=jobs)
        resp.content_type = falcon.MEDIA_HTML


class ScanResource:
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        # Parse form data
        form = await req.get_media()
        target_url = form.get("target_url")
        git_ref = form.get("git_ref")

        if not target_url:
            resp.status = falcon.HTTP_400
            resp.text = "Missing target_url"
            return

        # Create a new scan job
        scan_queue.create_job(target_url, git_ref)

        # In a real app we would raise an event or signal, but for now
        # the background worker will pick it up on its next polling cycle.

        # Redirect back to the dashboard to see the queued job
        raise falcon.HTTPFound("/")


class ReportResource:
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, report_id: str
    ) -> None:
        job = scan_queue.get_job(report_id)
        template = template_env.get_template("report.html")
        resp.text = template.render(title=f"Report {report_id}", job=job)
        resp.content_type = falcon.MEDIA_HTML


class QueueTableResource:
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        jobs = scan_queue.get_all_jobs()
        template = template_env.get_template("queue_table.html")
        resp.text = template.render(jobs=jobs)
        resp.content_type = falcon.MEDIA_HTML


import threading


def start_worker() -> None:
    # Run the async loop inside a new thread so it doesn't block Falcon's server
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(worker.worker_loop())


worker_thread = threading.Thread(target=start_worker, daemon=True)
worker_thread.start()

app = falcon.asgi.App()

# Serve static files
static_path = os.path.join(os.path.dirname(__file__), "static")
app.add_static_route("/static", static_path)

# Add routes
app.add_route("/", DashboardResource())
app.add_route("/scan", ScanResource())
app.add_route("/reports/{report_id}", ReportResource())
app.add_route("/api/queue_table", QueueTableResource())
