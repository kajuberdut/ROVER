"""rover/routes/api.py: Machine-to-machine JSON API routes.

This module is the designated home for all future authenticated JSON
endpoints. Current surface:
  - POST /api/ci/image-metadata; CI pipeline CI metadata ingestion

Planned additions (see ROADMAP for details):
  - §9.2  GET  /api/v1/releases/{release_id}/report; structured JSON release report
  - §15.1 POST /api/v1/releases/{release_id}/scan; CI/CD scan trigger
  - §15.2 GET  /api/v1/jobs/{job_id}/status; job status + policy verdict
"""

import falcon
import falcon.asgi

from rover import db, permissions


class CiImageMetadataResource:
    @falcon.before(permissions.require_api_write_token)
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        try:
            media = await req.get_media()
        except Exception:
            raise falcon.HTTPBadRequest(description="Invalid JSON payload")

        if not isinstance(media, dict):
            raise falcon.HTTPBadRequest(description="Payload must be a JSON object")

        image_hash = media.get("image_hash")
        repo_uri = media.get("repo_uri")
        commit_hash = media.get("commit_hash")
        metadata = media.get("metadata", {})
        image_tags = media.get("image_tags", [])
        ci_job_url = media.get("ci_job_url")

        if not all([image_hash, repo_uri, commit_hash]):
            raise falcon.HTTPBadRequest(
                description="Missing required fields: image_hash, repo_uri, commit_hash"
            )

        if not isinstance(metadata, dict):
            raise falcon.HTTPBadRequest(description="metadata must be a JSON object")

        success = db.add_ci_image_metadata(
            image_hash=str(image_hash),
            repo_uri=str(repo_uri),
            commit_hash=str(commit_hash),
            metadata_dict=metadata,
            image_tags=image_tags,
            ci_job_url=str(ci_job_url) if ci_job_url else None,
            user_sub=req.context.user.get("sub"),
            token_id=req.context.user.get("api_token_id"),
        )

        if not success:
            resp.status = falcon.HTTP_409
            resp.media = {"error": "Image metadata for this hash already exists."}
            return

        resp.status = falcon.HTTP_201
        resp.media = {"status": "ok"}


class OpenApiJsonResource:
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        from rover.openapi import get_openapi_schema

        resp.media = get_openapi_schema()
        resp.content_type = falcon.MEDIA_JSON


class OpenApiDocsResource:
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        from rover.openapi import SWAGGER_UI_HTML

        resp.text = SWAGGER_UI_HTML
        resp.content_type = falcon.MEDIA_HTML


class StarlightDocsResource:
    def __init__(self, dist_dir: str):
        import os

        self.dist_dir = os.path.abspath(dist_dir)

    async def on_get(
        self,
        req: falcon.asgi.Request,
        resp: falcon.asgi.Response,
        filepath: str = "",
    ) -> None:
        import os

        clean_path = (filepath or "").lstrip("/")
        target_path = os.path.join(self.dist_dir, clean_path)

        if os.path.isdir(target_path):
            target_path = os.path.join(target_path, "index.html")

        abs_target = os.path.abspath(target_path)
        if not abs_target.startswith(self.dist_dir):
            raise falcon.HTTPNotFound()

        if not os.path.exists(abs_target) or not os.path.isfile(abs_target):
            root_index = os.path.join(self.dist_dir, "index.html")
            if os.path.exists(root_index):
                abs_target = root_index
            else:
                raise falcon.HTTPNotFound()

        if abs_target.endswith(".html"):
            resp.content_type = falcon.MEDIA_HTML
        elif abs_target.endswith(".css"):
            resp.content_type = "text/css"
        elif abs_target.endswith(".js") or abs_target.endswith(".mjs"):
            resp.content_type = "application/javascript"
        elif abs_target.endswith(".webp"):
            resp.content_type = "image/webp"
        elif abs_target.endswith(".png"):
            resp.content_type = "image/png"
        elif abs_target.endswith(".svg"):
            resp.content_type = "image/svg+xml"
        elif abs_target.endswith(".json"):
            resp.content_type = falcon.MEDIA_JSON
        else:
            resp.content_type = "application/octet-stream"

        with open(abs_target, "rb") as f:
            content = f.read()
            if (
                "text" in resp.content_type
                or "json" in resp.content_type
                or "javascript" in resp.content_type
                or "html" in resp.content_type
            ):
                resp.text = content.decode("utf-8", errors="ignore")
            else:
                resp.data = content
