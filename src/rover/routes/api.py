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
