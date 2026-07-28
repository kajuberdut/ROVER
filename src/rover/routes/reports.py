"""rover/routes/reports.py: Report display and scan-trigger routes."""

from typing import Any

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
            # Also enqueue Semgrep SAST and Snyk scans for every repo
            db.create_semgrep_job(repo["url"], git_ref)
            db.create_snyk_job(repo["url"], git_ref)
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
        from rover import plugins

        plugin_jobs: dict[str, Any] = {}
        if job:
            target_url = job.get("target_url")
            git_ref = job.get("git_ref")

            linked = db.get_linked_targets(target_url) if target_url else {}
            candidate_targets: list[tuple[str, str | None]] = []
            if target_url:
                candidate_targets.append((target_url, git_ref))
            if linked.get("image_name") and linked["image_name"] != target_url:
                candidate_targets.append((linked["image_name"], git_ref))
            if (
                linked.get("source_repo_url")
                and linked["source_repo_url"] != target_url
            ):
                candidate_targets.append(
                    (
                        linked["source_repo_url"],
                        linked.get("source_git_ref") or git_ref,
                    )
                )

            for plugin in plugins.list_plugins():
                p_job = None
                if job and job.get("scanner_name") == plugin.name:
                    p_job = job
                else:
                    for t_url, t_ref in candidate_targets:
                        p_job = db.get_scanner_job_for_target(plugin.name, t_url, t_ref)
                        if not p_job:
                            p_job = db.get_scanner_job_for_target(plugin.name, t_url)
                        if p_job:
                            break

                plugin_jobs[plugin.name] = p_job

        trivy_job = plugin_jobs.get("trivy") or job
        semgrep_job = plugin_jobs.get("semgrep")
        snyk_job = plugin_jobs.get("snyk")

        back_url = req.get_param("back")
        back_label = req.get_param("back_label") or "Release"
        template = template_env.get_template("report.html")
        resp.text = template.render(
            user=getattr(req.context, "user", None),
            title=f"Report {report_id}",
            job=job,
            trivy_job=trivy_job,
            semgrep_job=semgrep_job,
            snyk_job=snyk_job,
            plugin_jobs=plugin_jobs,
            plugins=plugins.list_plugins(),
            back_url=back_url,
            back_label=back_label,
        )
        resp.content_type = falcon.MEDIA_HTML
