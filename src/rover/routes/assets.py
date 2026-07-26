"""rover/routes/assets.py: Asset creation and release-asset management routes.

Covers:
  - Direct asset creation: /repo, /image, /major_components
  - Release asset CRUD: add/remove assets on a release
  - HTMX partials: assets table and major-component cards
"""

import falcon
import falcon.asgi

from rover import db, permissions
from rover.routes._env import template_env


class RepositoryResource:
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        form = await req.get_media()
        target_url = form.get("target_url")
        if target_url:
            db.add_repository(target_url)
        referer = req.get_header("Referer", default="/")
        raise falcon.HTTPFound(referer)


class ImageResource:
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        form = await req.get_media()
        target_name = form.get("target_image_name") or form.get("target_name")
        if target_name:
            db.add_image(target_name)
        referer = req.get_header("Referer", default="/")
        if "?" not in referer:
            referer += "?tab=image"
        elif "tab=image" not in referer:
            referer += "&tab=image"
        raise falcon.HTTPFound(referer)


class MajorComponentResource:
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        form = await req.get_media()
        target_name = form.get("target_major_component_name") or form.get("target_name")
        target_version = form.get("target_major_component_version") or form.get(
            "target_version"
        )
        if target_name and target_version:
            db.add_major_component(target_name, target_version)
        referer = req.get_header("Referer", default="/")
        if "?" not in referer:
            referer += "?tab=major_component"
        elif "tab=major_component" not in referer:
            referer += "&tab=major_component"
        raise falcon.HTTPFound(referer)


class ReleaseAssetResource:
    @falcon.before(permissions.require_product_read_write)
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, release_id: str
    ) -> None:
        form = await req.get_media()
        asset_type = form.get("asset_type")
        asset_id = form.get("asset_id")
        git_ref = form.get("git_ref")

        # Handle auto-creation if asset_id is not provided
        if not asset_id:
            if asset_type == "repo":
                target_url = form.get("target_url")
                if target_url:
                    asset_id = db.add_repository(target_url)
            elif asset_type == "image":
                target_name = form.get("target_image_name") or form.get("target_name")
                if target_name:
                    asset_id = db.add_image(target_name)
            elif asset_type == "major_component":
                target_name = form.get("target_major_component_name") or form.get(
                    "target_name"
                )
                target_version = form.get("target_major_component_version") or form.get(
                    "target_version"
                )
                if target_name and target_version:
                    asset_id = db.add_major_component(target_name, target_version)

        # Images can also use git_ref as their container tag
        if asset_type and asset_id:
            db.add_release_asset(release_id, asset_type, asset_id, git_ref)
        raise falcon.HTTPFound(f"/releases/{release_id}")


class ReleaseAssetDetailResource:
    @falcon.before(permissions.require_product_read_write)
    async def on_post(
        self,
        req: falcon.asgi.Request,
        resp: falcon.asgi.Response,
        release_asset_id: str,
    ) -> None:
        form = await req.get_media()
        action = form.get("action")
        if action == "delete":
            db.remove_release_asset(release_asset_id)
        referer = req.get_header("Referer", default="/releases")
        raise falcon.HTTPFound(referer)


class ReleaseAssetsTableResource:
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, release_id: str
    ) -> None:
        assets = db.get_release_assets_with_latest_scans(release_id)
        release = db.get_release(release_id)
        template = template_env.get_template("release_assets_table.html")
        resp.text = template.render(
            user=getattr(req.context, "user", None), assets=assets, release=release
        )
        resp.content_type = falcon.MEDIA_HTML


class ReleaseMajorComponentCardsResource:
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, release_id: str
    ) -> None:
        assets = db.get_release_assets_with_latest_scans(release_id)
        major_component_assets = [
            a for a in assets if a["asset_type"] == "major_component"
        ]
        template = template_env.get_template("release_major_component_cards.html")
        resp.text = template.render(major_component_assets=major_component_assets)
        resp.content_type = falcon.MEDIA_HTML
