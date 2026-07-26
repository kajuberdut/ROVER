"""rover/routes/reports.py: Report display and scan-trigger routes."""

import falcon
import falcon.asgi

from rover import db, permissions
from rover.routes._env import template_env


class ScanResource:
    @falcon.before(permissions.require_product_read)
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
            target_url = form.get("target_url")
            if target_url:
                repo_id = db.add_repository(target_url)

            if not repo_id:
                resp.status = falcon.HTTP_400
                resp.text = "Missing repo_id or target_url"
                return

            repo = db.get_repository(repo_id)
            if not repo:
                resp.status = falcon.HTTP_404
                resp.text = "Repository not found"
                return

            # Create a new scan job
            db.create_job(repo["url"], git_ref, target_type="repo")
            # Also enqueue a Semgrep SAST scan for every repo (commit-hash cached in worker)
            db.create_semgrep_job(repo["url"], git_ref)
        elif scan_type == "image":
            target_name = form.get("target_image_name") or form.get("target_name")
            if target_name:
                image_id = db.add_image(target_name)

            if not image_id:
                resp.status = falcon.HTTP_400
                resp.text = "Missing image_id or target_name"
                return

            image = db.get_image(image_id)
            if not image:
                resp.status = falcon.HTTP_404
                resp.text = "Image not found"
                return

            # Create a new scan job
            db.create_job(image["name"], git_ref=git_ref, target_type="image")
        else:
            resp.status = falcon.HTTP_400
            resp.text = "Invalid scan_type"
            return

        # Redirect back to the dashboard to see the queued job
        raise falcon.HTTPFound("/")


class ReportResource:
    @falcon.before(permissions.require_product_read)
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, report_id: str
    ) -> None:
        job = db.get_job(report_id)
        semgrep_job = None
        if job:
            if job.get("target_type") == "repo":
                semgrep_job = db.get_semgrep_job_for_target(
                    job["target_url"], job.get("git_ref")
                )
            elif job.get("target_type") == "image":
                image = db.get_image_by_name(job["target_url"])
                if image and image.get("image_hash"):
                    ci_meta = db.get_ci_image_metadata(image["image_hash"])
                    if ci_meta and ci_meta.get("repo_uri"):
                        semgrep_job = db.get_semgrep_job_for_target(
                            ci_meta["repo_uri"], ci_meta.get("commit_hash")
                        )

        back_url = req.get_param("back")
        back_label = req.get_param("back_label") or "Release"
        template = template_env.get_template("report.html")
        resp.text = template.render(
            user=getattr(req.context, "user", None),
            title=f"Report {report_id}",
            job=job,
            semgrep_job=semgrep_job,
            back_url=back_url,
            back_label=back_label,
        )
        resp.content_type = falcon.MEDIA_HTML
