"""rover/routes/releases.py: Release lifecycle routes.

Covers: create, dashboard view, scan trigger, EOL status, and delete.
"""

import falcon
import falcon.asgi

from rover import db, permissions
from rover.routes._env import template_env


class ReleaseResource:
    @falcon.before(permissions.require_product_read_write)
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        form = await req.get_media()
        product_id = form.get("product_id")
        name = form.get("release_name")
        version = form.get("release_version")
        if product_id and name and version:
            db.add_release(product_id, name, version)
        referer = req.get_header("Referer", default="/")
        raise falcon.HTTPFound(referer)


class ReleaseDashboardResource:
    @falcon.before(permissions.require_product_read)
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, release_id: str
    ) -> None:
        release = db.get_release(release_id)
        if not release:
            raise falcon.HTTPFound("/?error=release_not_found")

        assets = db.get_release_assets_with_latest_scans(release_id)
        major_component_assets = [
            a for a in assets if a["asset_type"] == "major_component"
        ]
        repositories = db.get_all_repositories()
        images = db.get_all_images()
        major_components = db.get_all_major_components()

        product_role = None
        user = getattr(req.context, "user", None)
        if user:
            product_role = db.get_user_product_role(user["sub"], release["product_id"])

        credentials = db.get_credentials(release["product_id"])
        product = db.get_product(release["product_id"])
        template = template_env.get_template("release_dashboard.html")
        resp.text = template.render(
            user=user,
            product_role=product_role,
            title=f"Release: {release['name']} {release['version']}",
            release=release,
            product=product,
            assets=assets,
            major_component_assets=major_component_assets,
            repositories=repositories,
            images=images,
            major_components=major_components,
            credentials=credentials,
        )
        resp.content_type = falcon.MEDIA_HTML


class ReleaseScanResource:
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, release_id: str
    ) -> None:
        """Trigger a scan for all assets within this release."""
        assets = db.get_release_assets_with_latest_scans(release_id)
        for asset in assets:
            if asset["asset_type"] == "repo":
                db.create_job(
                    target_url=asset["asset_name"],
                    target_type="repo",
                    git_ref=asset["git_ref"],
                )
                # Also enqueue Semgrep and Snyk (worker will use commit-hash cache if already scanned)
                db.create_semgrep_job(
                    target_url=asset["asset_name"],
                    git_ref=asset.get("git_ref"),
                )
                db.create_snyk_job(
                    target_url=asset["asset_name"],
                    git_ref=asset.get("git_ref"),
                )
            elif asset["asset_type"] == "image":
                db.create_job(
                    target_url=asset["asset_name"],
                    target_type="image",
                    git_ref=asset.get("git_ref"),
                )
                db.create_snyk_job(
                    target_url=asset["asset_name"],
                    git_ref=asset.get("git_ref"),
                )
                if asset.get("source_repo_url"):
                    db.create_semgrep_job(
                        target_url=asset["source_repo_url"],
                        git_ref=asset.get("image_source_git_ref"),
                    )

            elif asset["asset_type"] == "major_component":
                db.create_job(
                    target_url=asset["asset_name"],
                    target_type="major_component",
                    git_ref=asset.get("git_ref"),
                )

        referer = req.get_header("Referer", default=f"/releases/{release_id}")
        raise falcon.HTTPFound(referer)


class ReleaseEolResource:
    @falcon.before(permissions.require_product_admin)
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, release_id: str
    ) -> None:
        form = await req.get_media()
        action = form.get("action")
        if action == "mark_eol":
            db.update_release_eol_status(release_id, is_eol=True)
        elif action == "unmark_eol":
            db.update_release_eol_status(release_id, is_eol=False)
        referer = req.get_header("Referer", default=f"/releases/{release_id}")
        raise falcon.HTTPFound(referer)


class AssetScanResource:
    @falcon.before(permissions.require_product_read_write)
    async def on_post(
        self,
        req: falcon.asgi.Request,
        resp: falcon.asgi.Response,
        release_asset_id: str,
    ) -> None:
        """Trigger a scan for a single release asset."""
        asset = db.get_release_asset_details(release_asset_id)
        if not asset or not asset.get("asset_name"):
            resp.status = falcon.HTTP_404
            resp.media = {"error": "Release asset not found"}
            return

        scanner = req.get_param("scanner", default="all")
        if req.content_length:
            import contextlib

            with contextlib.suppress(Exception):
                media = await req.get_media()
                if isinstance(media, dict) and "scanner" in media:
                    scanner = media["scanner"]

        job_ids = []
        target_name = asset["asset_name"]
        asset_type = asset["asset_type"]
        git_ref = asset.get("git_ref")

        if asset_type == "repo":
            if scanner in ("trivy", "all"):
                job_ids.append(
                    db.create_job(
                        target_url=target_name,
                        target_type="repo",
                        git_ref=git_ref,
                    )
                )
            if scanner in ("semgrep", "all"):
                job_ids.append(
                    db.create_semgrep_job(
                        target_url=target_name,
                        git_ref=git_ref,
                    )
                )
            if scanner in ("snyk", "all"):
                job_ids.append(
                    db.create_snyk_job(
                        target_url=target_name,
                        git_ref=git_ref,
                    )
                )

        elif asset_type == "image":
            if scanner in ("trivy", "all"):
                job_ids.append(
                    db.create_job(
                        target_url=target_name,
                        target_type="image",
                        git_ref=git_ref,
                    )
                )
            if scanner in ("snyk", "all"):
                job_ids.append(
                    db.create_snyk_job(
                        target_url=target_name,
                        git_ref=git_ref,
                    )
                )
            if scanner in ("semgrep", "all") and asset.get("source_repo_url"):
                job_ids.append(
                    db.create_semgrep_job(
                        target_url=asset["source_repo_url"],
                        git_ref=asset.get("image_source_git_ref"),
                    )
                )

        elif asset_type == "major_component":
            if scanner in ("trivy", "all"):
                job_ids.append(
                    db.create_job(
                        target_url=target_name,
                        target_type="major_component",
                        git_ref=git_ref,
                    )
                )

        accept_header = req.get_header("Accept", default="")
        content_type = req.get_header("Content-Type", default="")
        if (
            "application/json" in accept_header
            or "application/json" in content_type
            or req.get_param("format") == "json"
        ):
            resp.status = falcon.HTTP_201
            resp.media = {
                "status": "queued",
                "release_asset_id": release_asset_id,
                "dispatched_jobs": job_ids,
            }
        else:
            referer = req.get_header(
                "Referer", default=f"/releases/{asset['release_id']}"
            )
            raise falcon.HTTPFound(referer)


class ReleaseDeleteResource:
    @falcon.before(permissions.require_product_admin)
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, release_id: str
    ) -> None:
        release = db.get_release(release_id)
        if not release:
            raise falcon.HTTPFound("/?error=release_not_found")
        product_id = release["product_id"]
        db.delete_release(release_id)
        raise falcon.HTTPFound(f"/products/{product_id}")
