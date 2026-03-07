import json
import logging
import subprocess
import tempfile
import urllib.error
import urllib.request

# ruff: noqa: S603, S607
from testcontainers.core.container import DockerContainer  # type: ignore

logger = logging.getLogger(__name__)


from typing import Any, cast

from rover import scan_queue


def run_major_component_scan(
    target_name: str, target_version: str
) -> tuple[dict[str, Any], str, str | None]:
    """
    Fetches the end of life date for a given component and version.
    Utilizes a 28-day database cache to avoid rate limiting.
    """
    logger.info(f"Checking EOL data for {target_name} version {target_version}")

    cached_json = scan_queue.get_cached_eol_data(target_name, target_version)
    if cached_json:
        logger.info(f"Using cached EOL data for {target_name} v{target_version}")
        return json.loads(cached_json), "eol_cache", "cached"

    url = f"https://endoflife.date/api/{target_name}/{target_version}.json"
    req = urllib.request.Request(url, headers={"User-Agent": "RoverScanner/1.0"})  # noqa: S310

    try:
        with urllib.request.urlopen(req) as response:  # noqa: S310
            data = response.read().decode("utf-8")
            parsed_data = json.loads(data)

            # Store the raw validated json exactly into our cache
            scan_queue.set_cached_eol_data(
                target_name, target_version, json.dumps(parsed_data)
            )

            return parsed_data, "eol_api", "fresh"
    except urllib.error.HTTPError as e:
        logger.error(f"HTTP error fetching EOL data: {e.code} - {e.reason}")
        if e.code == 404:
            raise Exception(f"EOL data not found for {target_name} v{target_version}")
        raise Exception(f"Failed to fetch EOL data: {e.reason}")
    except Exception as e:
        logger.error(f"Error fetching EOL data: {e}")
        raise Exception("Failed to retrieve EOL data from endoflife.date API")


def run_trivy_scan(
    target_url: str, git_ref: str | None = None, target_type: str = "repo"
) -> tuple[dict[str, Any], str, str | None]:
    """
    Runs a Trivy CVE scan against a git repository or Docker image using Testcontainers.
    """
    logger.info(
        f"Starting Trivy scan for {target_type} {target_url} (ref {git_ref or 'HEAD'})"
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        commit_hash = "latest"
        tags_str = None

        if target_type == "repo":
            # Clone the repository locally
            try:
                subprocess.run(  # noqa: S603, S607
                    ["git", "clone", target_url, tmpdir],
                    check=True,
                    capture_output=True,
                )
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to clone repository: {e.stderr.decode('utf-8')}")
                raise Exception("Failed to clone target repository")

            if git_ref:
                try:
                    subprocess.run(  # noqa: S603, S607
                        ["git", "checkout", git_ref],
                        cwd=tmpdir,
                        check=True,
                        capture_output=True,
                    )
                except subprocess.CalledProcessError as e:
                    logger.error(
                        f"Failed to checkout ref {git_ref}: {e.stderr.decode('utf-8')}"
                    )
                    raise Exception(f"Failed to checkout git reference: {git_ref}")

            # Capture metadata
            try:
                res = subprocess.run(  # noqa: S603, S607
                    ["git", "rev-parse", "HEAD"],
                    cwd=tmpdir,
                    check=True,
                    capture_output=True,
                    text=True,
                )
                commit_hash = res.stdout.strip()

                res = subprocess.run(  # noqa: S603, S607
                    ["git", "tag", "--points-at", "HEAD"],
                    cwd=tmpdir,
                    check=True,
                    capture_output=True,
                    text=True,
                )
                tags = [t.strip() for t in res.stdout.split("\n") if t.strip()]
                tags_str = ", ".join(tags) if tags else None
            except subprocess.CalledProcessError as e:
                logger.warning(f"Failed to capture git metadata: {e}")
                commit_hash = "unknown"
                tags_str = None
        elif target_type == "image":
            # If git_ref is provided, use it as the image tag, unless target_url already has a tag
            image_target = target_url
            if git_ref and ":" not in image_target.split("/")[-1]:
                image_target = f"{target_url}:{git_ref}"
            tags_str = image_target
            commit_hash = "latest"  # Images don't have git commits in the same way

        container = DockerContainer("aquasec/trivy:latest")

        # Configure Trivy database cache using an ephemeral named volume
        container.with_env("TRIVY_CACHE_DIR", "/trivy-cache")
        container.with_volume_mapping(
            "trivy-vulnerability-db-cache", "/trivy-cache", "rw"
        )
        # Mount the Docker socket so Trivy can scan images
        container.with_volume_mapping(
            "/var/run/docker.sock", "/var/run/docker.sock", "ro"
        )

        if target_type == "repo":
            # Tell the container to execute the repo scan and output json for the specific commit we resolved
            container.with_command(f"repo {target_url} --commit {commit_hash} -f json")
        else:
            # Tell the container to execute the image scan
            container.with_command(f"image {image_target} -f json")

        try:
            container.start()

            # Wait for the container to exit and get the logs
            client = container.get_docker_client()
            result = client.client.containers.get(container.get_wrapped_container().id)

            exit_code = result.wait()["StatusCode"]

            logs = container.get_logs()
            stdout = logs[0].decode("utf-8")
            stderr = logs[1].decode("utf-8")

            logger.info(f"Trivy stdout (first 200 chars): {stdout[:200]}")
            logger.info(f"Trivy stderr: {stderr}")

            if exit_code != 0:
                logger.warning(
                    f"Trivy scan exited with code {exit_code}. Stderr: {stderr}"
                )

            try:
                json_start = stdout.find("{")
                json_end = stdout.rfind("}") + 1
                if json_start >= 0 and json_end > json_start:
                    json_str = stdout[json_start:json_end]
                    scan_results = cast(dict[str, Any], json.loads(json_str))
                else:
                    if exit_code != 0:
                        raise Exception(f"Trivy failed with exit code {exit_code}")
                    scan_results = {"Results": []}

                return scan_results, commit_hash, tags_str

            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Trivy JSON output. Error: {e}")
                logger.error(f"Raw output: {stdout}")
                raise Exception("Failed to parse vulnerability report")

        finally:
            container.stop()
