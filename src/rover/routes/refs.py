"""rover/routes/refs.py — Git branch/tag and container image tag query routes.

All resources in this module make subprocess calls (``git ls-remote``
or ``skopeo list-tags``) to resolve remote refs without cloning.
``ImageLinkRepoResource`` additionally creates a CI metadata record and
enqueues a Semgrep scan when a user manually links a source repository
to a container image.
"""

import asyncio
import json
import subprocess

import falcon
import falcon.asgi

from rover import scan_queue, scanner


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


class RemoteRepoRefsResource:
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        url = req.get_param("url")
        if not url:
            resp.status = falcon.HTTP_400
            resp.text = json.dumps({"error": "Missing url parameter"})
            return

        try:
            # Run git ls-remote to securely fetch branches and tags from arbitrary url
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


class ImageRefsResource:
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, image_id: str
    ) -> None:
        image = scan_queue.get_image(image_id)
        if not image:
            resp.status = falcon.HTTP_404
            resp.text = json.dumps({"error": "Image not found"})
            return

        image_name = image["name"]

        # If the user didn't specify a registry, skopeo defaults to docker.io
        # but requires the docker:// prefix
        url = f"docker://{image_name}"
        try:
            # Run skopeo list-tags to securely fetch tags
            result = subprocess.run(  # noqa: S603
                ["skopeo", "list-tags", url],  # noqa: S607
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            data = json.loads(result.stdout)
            tags = data.get("Tags", [])

            resp.text = json.dumps({"tags": sorted(tags)})
            resp.content_type = falcon.MEDIA_JSON
        except subprocess.TimeoutExpired:
            resp.status = falcon.HTTP_504
            resp.text = json.dumps({"error": "Timeout fetching tags"})
        except subprocess.CalledProcessError as e:
            resp.status = falcon.HTTP_500
            resp.text = json.dumps({"error": f"Failed to fetch tags: {e.stderr}"})
        except json.JSONDecodeError:
            resp.status = falcon.HTTP_500
            resp.text = json.dumps({"error": "Invalid JSON response from skopeo"})


class ImageLinkRepoResource:
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, image_id: str
    ) -> None:
        """Manually link a source code repository to an image."""
        user = req.context.get("user")
        if not user:
            raise falcon.HTTPUnauthorized()

        # Allow if system admin, or if they have *any* product role
        is_system_admin = user.get("role") == "system_admin"
        if not is_system_admin:
            user_products = scan_queue.get_user_product_ids(user["sub"])
            if not user_products:
                raise falcon.HTTPForbidden(
                    title="Forbidden",
                    description="Insufficient permissions to modify image metadata.",
                )

        form = await req.get_media()
        source_repo_url = form.get("source_repo_url")
        source_git_ref = form.get("source_git_ref")

        image = scan_queue.get_image(image_id)
        if not image:
            raise falcon.HTTPNotFound(description="Image not found")

        if source_repo_url:
            image_hash = image.get("image_hash")
            if not image_hash:
                image_hash = await asyncio.to_thread(
                    scanner.resolve_image_hash, image["name"]
                )
                if image_hash:
                    scan_queue.update_image_hash(image_id, image_hash)
                else:
                    raise falcon.HTTPInternalServerError(
                        description="Could not resolve image hash for this image."
                    )

            scan_queue.add_ci_image_metadata(
                image_hash=image_hash,
                repo_uri=source_repo_url,
                commit_hash=source_git_ref or "",
                metadata_dict={"source": "manual_link"},
                user_sub=user["sub"],
            )

            scan_queue.add_repository(source_repo_url)
            scan_queue.create_semgrep_job(
                source_repo_url, git_ref=source_git_ref or None
            )
            resp.media = {
                "status": "ok",
                "message": "Repository linked and scan enqueued.",
            }
        else:
            resp.status = falcon.HTTP_400
            resp.media = {"status": "error", "message": "source_repo_url is required."}


class RemoteImageRefsResource:
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        name = req.get_param("name")
        if not name:
            resp.status = falcon.HTTP_400
            resp.text = json.dumps({"error": "Missing name parameter"})
            return

        url = f"docker://{name}"
        try:
            result = subprocess.run(  # noqa: S603
                ["skopeo", "list-tags", url],  # noqa: S607
                capture_output=True,
                text=True,
                check=True,
                timeout=10,
            )
            data = json.loads(result.stdout)
            tags = data.get("Tags", [])

            resp.text = json.dumps({"tags": sorted(tags)})
            resp.content_type = falcon.MEDIA_JSON
        except subprocess.TimeoutExpired:
            resp.status = falcon.HTTP_504
            resp.text = json.dumps({"error": "Timeout fetching tags"})
        except subprocess.CalledProcessError as e:
            resp.status = falcon.HTTP_500
            resp.text = json.dumps({"error": f"Failed to fetch tags: {e.stderr}"})
        except json.JSONDecodeError:
            resp.status = falcon.HTTP_500
            resp.text = json.dumps({"error": "Invalid JSON response from skopeo"})
