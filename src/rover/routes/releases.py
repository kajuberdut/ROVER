"""rover/routes/releases.py — Release lifecycle routes.

Covers: create, dashboard view, scan trigger, EOL status, and delete.
"""

import falcon
import falcon.asgi

from rover import permissions, scan_queue
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
            scan_queue.add_release(product_id, name, version)
        referer = req.get_header("Referer", default="/")
        raise falcon.HTTPFound(referer)


class ReleaseDashboardResource:
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, release_id: str
    ) -> None:
        release = scan_queue.get_release(release_id)
        if not release:
            raise falcon.HTTPFound("/?error=release_not_found")

        assets = scan_queue.get_release_assets_with_latest_scans(release_id)
        major_component_assets = [
            a for a in assets if a["asset_type"] == "major_component"
        ]
        repositories = scan_queue.get_all_repositories()
        images = scan_queue.get_all_images()
        major_components = scan_queue.get_all_major_components()

        product_role = None
        user = getattr(req.context, "user", None)
        if user:
            product_role = scan_queue.get_user_product_role(
                user["sub"], release["product_id"]
            )

        template = template_env.get_template("release_dashboard.html")
        resp.text = template.render(
            user=user,
            product_role=product_role,
            title=f"Release: {release['name']} {release['version']}",
            release=release,
            assets=assets,
            major_component_assets=major_component_assets,
            repositories=repositories,
            images=images,
            major_components=major_components,
        )
        resp.content_type = falcon.MEDIA_HTML


class ReleaseScanResource:
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, release_id: str
    ) -> None:
        """Trigger a scan for all assets within this release."""
        assets = scan_queue.get_release_assets_with_latest_scans(release_id)
        for asset in assets:
            if asset["asset_type"] == "repo":
                scan_queue.create_job(
                    target_url=asset["asset_name"],
                    target_type="repo",
                    git_ref=asset["git_ref"],
                )
                # Also enqueue Semgrep (worker will use commit-hash cache if already scanned)
                scan_queue.create_semgrep_job(
                    target_url=asset["asset_name"],
                    git_ref=asset.get("git_ref"),
                )
            elif asset["asset_type"] == "image":
                scan_queue.create_job(
                    target_url=asset["asset_name"],
                    target_type="image",
                    git_ref=asset.get("git_ref"),
                )
            elif asset["asset_type"] == "major_component":
                scan_queue.create_job(
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
            scan_queue.update_release_eol_status(release_id, is_eol=True)
        elif action == "unmark_eol":
            scan_queue.update_release_eol_status(release_id, is_eol=False)
        referer = req.get_header("Referer", default=f"/releases/{release_id}")
        raise falcon.HTTPFound(referer)


class ReleaseDeleteResource:
    @falcon.before(permissions.require_product_admin)
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, release_id: str
    ) -> None:
        release = scan_queue.get_release(release_id)
        if not release:
            raise falcon.HTTPFound("/?error=release_not_found")
        product_id = release["product_id"]
        scan_queue.delete_release(release_id)
        raise falcon.HTTPFound(f"/products/{product_id}")
