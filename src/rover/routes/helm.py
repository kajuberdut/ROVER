"""rover/routes/helm.py: Helm chart ingestion routes."""

import asyncio

import falcon
import falcon.asgi

from rover import db, permissions, scanner


class HelmRepoChartsResource:
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        url = req.get_param("url")
        if not url:
            resp.media = {"error": "Missing url parameter"}
            resp.status = falcon.HTTP_400
            return

        try:
            charts = await asyncio.to_thread(scanner.fetch_helm_chart_versions, url)
            resp.media = charts
        except Exception as e:
            resp.media = {"error": str(e)}
            resp.status = falcon.HTTP_500


class ReleaseHelmResource:
    @falcon.before(permissions.require_product_read_write)
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        form = await req.get_media()
        product_id = form.get("product_id")
        repo_url = form.get("helm_repo_url")
        chart_name = form.get("chart_name")
        chart_version = form.get("chart_version")

        if not (product_id and repo_url and chart_name and chart_version):
            referer = req.get_header("Referer", default="/")
            raise falcon.HTTPFound(referer)

        release_id = db.add_release(product_id, chart_name, chart_version)

        try:
            images = await asyncio.to_thread(
                scanner.run_helm_ingestion, repo_url, chart_name, chart_version
            )
            for img in images:
                image_id = db.add_image(img)
                db.add_release_asset(release_id, "image", image_id)
        except Exception:
            # Provide an error parameter on redirect so the user knows ingestion failed
            raise falcon.HTTPFound(f"/products/{product_id}?error=helm_ingest_failed")

        raise falcon.HTTPFound(f"/releases/{release_id}")
