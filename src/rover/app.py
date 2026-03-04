import asyncio
import json
import os
import subprocess

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
        repositories = scan_queue.get_all_repositories()
        images = scan_queue.get_all_images()
        template = template_env.get_template("dashboard.html")
        resp.text = template.render(
            title="R.O.V.E.R Dashboard",
            jobs=jobs,
            repositories=repositories,
            images=images,
        )
        resp.content_type = falcon.MEDIA_HTML


class RepositoryResource:
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        form = await req.get_media()
        target_url = form.get("target_url")
        if target_url:
            scan_queue.add_repository(target_url)
        raise falcon.HTTPFound("/")


class ImageResource:
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        form = await req.get_media()
        target_name = form.get("target_name")
        if target_name:
            scan_queue.add_image(target_name)
        raise falcon.HTTPFound("/")


class RepoRefsResource:
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, repo_id: str
    ) -> None:
        repo = scan_queue.get_repository(repo_id)
        if not repo:
            resp.status = falcon.HTTP_404
            resp.text = json.dumps({"error": "Repository not found"})
            return

        url = repo["url"]
        try:
            # Run git ls-remote to securely fetch branches and tags
            result = subprocess.run(  # noqa: S603
                ["git", "ls-remote", "--heads", "--tags", url],  # noqa: S607
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )

            branches = []
            tags = []
            for line in result.stdout.splitlines():
                if not line:
                    continue
                parts = line.split("\t")
                if len(parts) != 2:
                    continue
                ref = parts[1]

                if ref.startswith("refs/heads/"):
                    branches.append(ref[len("refs/heads/") :])
                elif ref.startswith("refs/tags/"):
                    # Remove the ^{} suffix from dereferenced tags
                    clean_tag = ref[len("refs/tags/") :]
                    if clean_tag.endswith("^{}"):
                        clean_tag = clean_tag[:-3]
                    if clean_tag not in tags:
                        tags.append(clean_tag)

            resp.text = json.dumps({"branches": sorted(branches), "tags": sorted(tags)})
            resp.content_type = falcon.MEDIA_JSON
        except subprocess.TimeoutExpired:
            resp.status = falcon.HTTP_504
            resp.text = json.dumps({"error": "Timeout fetching refs"})
        except subprocess.CalledProcessError as e:
            resp.status = falcon.HTTP_500
            resp.text = json.dumps({"error": f"Failed to fetch refs: {e.stderr}"})


class ScanResource:
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        # Parse form data
        form = await req.get_media()
        repo_id = form.get("repo_id")
        image_id = form.get("image_id")
        git_ref = form.get("git_ref")
        scan_type = form.get("scan_type", "repo")

        if scan_type == "repo":
            if not repo_id:
                resp.status = falcon.HTTP_400
                resp.text = "Missing repo_id"
                return

            repo = scan_queue.get_repository(repo_id)
            if not repo:
                resp.status = falcon.HTTP_404
                resp.text = "Repository not found"
                return

            # Create a new scan job
            scan_queue.create_job(repo["url"], git_ref, target_type="repo")
        elif scan_type == "image":
            if not image_id:
                resp.status = falcon.HTTP_400
                resp.text = "Missing image_id"
                return

            image = scan_queue.get_image(image_id)
            if not image:
                resp.status = falcon.HTTP_404
                resp.text = "Image not found"
                return

            # Create a new scan job
            scan_queue.create_job(image["name"], git_ref=None, target_type="image")
        else:
            resp.status = falcon.HTTP_400
            resp.text = "Invalid scan_type"
            return

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
app.add_route("/repo", RepositoryResource())
app.add_route("/image", ImageResource())
app.add_route("/reports/{report_id}", ReportResource())
app.add_route("/api/queue_table", QueueTableResource())
app.add_route("/api/repos/{repo_id}/refs", RepoRefsResource())
