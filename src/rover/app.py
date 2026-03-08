import asyncio
import json
import os
import subprocess
from datetime import datetime

import falcon
import falcon.asgi
import jinja2

from rover import config, scan_queue, worker, auth

# Configure Jinja2 environment
template_dir = os.path.join(os.path.dirname(__file__), "templates")
template_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir),
    autoescape=jinja2.select_autoescape(["html", "xml"]),
)
template_env.filters["loadjson"] = json.loads


def humanize_time(date_str: str | None) -> str:
    if not date_str:
        return "N/A"
    try:
        # Assuming date_str is 'YYYY-MM-DD HH:MM:SS'
        dt = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
        now = datetime.now()
        diff = now - dt
        if diff.days == 0:
            if diff.seconds < 60:
                return "Just now"
            elif diff.seconds < 3600:
                mins = diff.seconds // 60
                return f"{mins} min{'s' if mins > 1 else ''} ago"
            else:
                hours = diff.seconds // 3600
                return f"{hours} hour{'s' if hours > 1 else ''} ago"
        elif diff.days == 1:
            return "Yesterday"
        else:
            return dt.strftime("%b %d, %Y")
    except Exception:
        return date_str


template_env.filters["humanize_time"] = humanize_time


def short_url(url: str | None) -> str:
    if not url:
        return ""
    if url.startswith("http://"):
        url = url[7:]
    elif url.startswith("https://"):
        url = url[8:]
    if "/" in url:
        return url.split("/", 1)[1]
    return url


template_env.filters["short_url"] = short_url


class ConfigResource:
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        raw_toml = config.read_raw_config()
        template = template_env.get_template("config.html")
        resp.text = template.render(user=getattr(req.context, "user", None), title="Configuration", raw_toml=raw_toml)
        resp.content_type = falcon.MEDIA_HTML

    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        form = await req.get_media()
        raw_toml = form.get("raw_toml", "")
        template = template_env.get_template("config.html")
        try:
            config.save_raw_config(raw_toml)
            saved_toml = config.read_raw_config()
            # Update global settings in memory
            config.settings = config.load_config()
            resp.text = template.render(
                user=getattr(req.context, "user", None), title="Configuration", raw_toml=saved_toml, success=True
            )
        except Exception as e:
            resp.text = template.render(
                user=getattr(req.context, "user", None), title="Configuration", raw_toml=raw_toml, error=str(e)
            )
            resp.status = falcon.HTTP_400
        resp.content_type = falcon.MEDIA_HTML


class DashboardResource:
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        jobs = scan_queue.get_all_jobs()
        repositories = scan_queue.get_all_repositories()
        images = scan_queue.get_all_images()
        products = scan_queue.get_all_products()
        releases = scan_queue.get_all_releases()
        major_components = scan_queue.get_all_major_components()
        template = template_env.get_template("dashboard.html")
        resp.text = template.render(
            user=getattr(req.context, "user", None),
            title="R.O.V.E.R Dashboard",
            jobs=jobs,
            repositories=repositories,
            images=images,
            products=products,
            releases=releases,
            major_components=major_components,
            scan_queue=scan_queue,
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
        referer = req.get_header("Referer", default="/")
        raise falcon.HTTPFound(referer)


class ImageResource:
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        form = await req.get_media()
        target_name = form.get("target_image_name") or form.get("target_name")
        if target_name:
            scan_queue.add_image(target_name)
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
            scan_queue.add_major_component(target_name, target_version)
        referer = req.get_header("Referer", default="/")
        if "?" not in referer:
            referer += "?tab=major_component"
        elif "tab=major_component" not in referer:
            referer += "&tab=major_component"
        raise falcon.HTTPFound(referer)


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
            target_url = form.get("target_url")
            if target_url:
                repo_id = scan_queue.add_repository(target_url)

            if not repo_id:
                resp.status = falcon.HTTP_400
                resp.text = "Missing repo_id or target_url"
                return

            repo = scan_queue.get_repository(repo_id)
            if not repo:
                resp.status = falcon.HTTP_404
                resp.text = "Repository not found"
                return

            # Create a new scan job
            scan_queue.create_job(repo["url"], git_ref, target_type="repo")
        elif scan_type == "image":
            target_name = form.get("target_image_name") or form.get("target_name")
            if target_name:
                image_id = scan_queue.add_image(target_name)

            if not image_id:
                resp.status = falcon.HTTP_400
                resp.text = "Missing image_id or target_name"
                return

            image = scan_queue.get_image(image_id)
            if not image:
                resp.status = falcon.HTTP_404
                resp.text = "Image not found"
                return

            # Create a new scan job
            scan_queue.create_job(image["name"], git_ref=git_ref, target_type="image")
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
        resp.text = template.render(user=getattr(req.context, "user", None), title=f"Report {report_id}", job=job)
        resp.content_type = falcon.MEDIA_HTML


class QueueTableResource:
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        jobs = scan_queue.get_all_jobs()
        template = template_env.get_template("queue_table.html")
        resp.text = template.render(jobs=jobs)
        resp.content_type = falcon.MEDIA_HTML


class ProductResource:
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        form = await req.get_media()
        name = form.get("product_name")
        description = form.get("product_description", "")
        if name:
            scan_queue.add_product(name, description)
        referer = req.get_header("Referer", default="/")
        raise falcon.HTTPFound(referer)


class ProductDashboardResource:
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, product_id: str
    ) -> None:
        product = scan_queue.get_product(product_id)
        if not product:
            raise falcon.HTTPFound("/?error=product_not_found")

        releases = scan_queue.get_product_releases(product_id)
        template = template_env.get_template("product_dashboard.html")
        resp.text = template.render(
            user=getattr(req.context, "user", None),
            title=f"Product: {product['name']}",
            product=product,
            releases=releases,
            scan_queue=scan_queue,
        )
        resp.content_type = falcon.MEDIA_HTML


class ReleaseResource:
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


class ReleaseAssetResource:
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
                    asset_id = scan_queue.add_repository(target_url)
            elif asset_type == "image":
                target_name = form.get("target_image_name") or form.get("target_name")
                if target_name:
                    asset_id = scan_queue.add_image(target_name)
            elif asset_type == "major_component":
                target_name = form.get("target_major_component_name") or form.get(
                    "target_name"
                )
                target_version = form.get("target_major_component_version") or form.get(
                    "target_version"
                )
                if target_name and target_version:
                    asset_id = scan_queue.add_major_component(
                        target_name, target_version
                    )

        # Images can also use git_ref as their container tag

        if asset_type and asset_id:
            scan_queue.add_release_asset(release_id, asset_type, asset_id, git_ref)
        raise falcon.HTTPFound(f"/releases/{release_id}")


class ReleaseAssetDetailResource:
    async def on_post(
        self,
        req: falcon.asgi.Request,
        resp: falcon.asgi.Response,
        release_asset_id: str,
    ) -> None:
        form = await req.get_media()
        action = form.get("action")
        if action == "delete":
            scan_queue.remove_release_asset(release_asset_id)
        referer = req.get_header("Referer", default="/releases")
        raise falcon.HTTPFound(referer)


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


class ReleaseDashboardResource:
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, release_id: str
    ) -> None:
        release = scan_queue.get_release(release_id)
        if not release:
            # Re-route to the dashboard ('/') and display a clean Pico CSS
            # toast notification explaining the release was not found.
            raise falcon.HTTPFound("/?error=release_not_found")

        assets = scan_queue.get_release_assets_with_latest_scans(release_id)
        major_component_assets = [
            a for a in assets if a["asset_type"] == "major_component"
        ]
        repositories = scan_queue.get_all_repositories()
        images = scan_queue.get_all_images()
        major_components = scan_queue.get_all_major_components()

        template = template_env.get_template("release_dashboard.html")
        resp.text = template.render(
            user=getattr(req.context, "user", None),
            title=f"Release: {release['name']} {release['version']}",
            release=release,
            assets=assets,
            major_component_assets=major_component_assets,
            repositories=repositories,
            images=images,
            major_components=major_components,
        )
        resp.content_type = falcon.MEDIA_HTML


class ReleaseAssetsTableResource:
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, release_id: str
    ) -> None:
        assets = scan_queue.get_release_assets_with_latest_scans(release_id)
        template = template_env.get_template("release_assets_table.html")
        resp.text = template.render(assets=assets)
        resp.content_type = falcon.MEDIA_HTML


class ReleaseMajorComponentCardsResource:
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, release_id: str
    ) -> None:
        assets = scan_queue.get_release_assets_with_latest_scans(release_id)
        major_component_assets = [
            a for a in assets if a["asset_type"] == "major_component"
        ]
        template = template_env.get_template("release_major_component_cards.html")
        resp.text = template.render(major_component_assets=major_component_assets)
        resp.content_type = falcon.MEDIA_HTML


class ReleaseEolResource:
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


import threading


def start_worker() -> None:
    # Run the async loop inside a new thread so it doesn't block Falcon's server
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(worker.worker_loop())


worker_thread = threading.Thread(target=start_worker, daemon=True)
worker_thread.start()

from rover.eol_proxy import EolProxyAllResource, EolProxyProductResource

app = falcon.asgi.App(middleware=[auth.RequireAuthMiddleware()])
app.add_route("/api/eol/all", EolProxyAllResource())
app.add_route("/api/eol/{product}", EolProxyProductResource())

# Serve static files
static_path = os.path.join(os.path.dirname(__file__), "static")
app.add_static_route("/static", static_path)

# Add auth routes
app.add_route("/login", auth.LoginResource())
app.add_route("/callback", auth.CallbackResource())
app.add_route("/logout", auth.LogoutResource())

# Add routes
app.add_route("/", DashboardResource())
app.add_route("/config", ConfigResource())
app.add_route("/scan", ScanResource())
app.add_route("/repo", RepositoryResource())
app.add_route("/image", ImageResource())
app.add_route("/major_components", MajorComponentResource())
app.add_route("/reports/{report_id}", ReportResource())
app.add_route("/api/queue_table", QueueTableResource())
app.add_route("/api/repos/{repo_id}/refs", RepoRefsResource())
app.add_route("/api/images/{image_id}/refs", ImageRefsResource())
app.add_route("/api/remote_refs/repo", RemoteRepoRefsResource())
app.add_route("/api/remote_refs/image", RemoteImageRefsResource())
app.add_route("/products", ProductResource())
app.add_route("/products/{product_id}", ProductDashboardResource())
app.add_route("/releases", ReleaseResource())
app.add_route("/releases/{release_id}/assets", ReleaseAssetResource())
app.add_route("/releases/assets/{release_asset_id}", ReleaseAssetDetailResource())
app.add_route("/releases/{release_id}/scan", ReleaseScanResource())
app.add_route("/releases/{release_id}/eol", ReleaseEolResource())
app.add_route("/api/releases/{release_id}/assets_table", ReleaseAssetsTableResource())
app.add_route(
    "/api/releases/{release_id}/major_component_cards",
    ReleaseMajorComponentCardsResource(),
)
app.add_route("/releases/{release_id}", ReleaseDashboardResource())
