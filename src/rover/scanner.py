import json
import logging
import subprocess
import tempfile

# ruff: noqa: S603, S607
from testcontainers.core.container import DockerContainer  # type: ignore

logger = logging.getLogger(__name__)


from typing import Any, cast


def run_trivy_scan(
    target_url: str, git_ref: str | None = None
) -> tuple[dict[str, Any], str, str | None]:
    """
    Runs a Trivy CVE scan against a git repository using Testcontainers.
    Clones the repository locally first to support checking out specific tags/commits.
    """
    logger.info(f"Starting Trivy scan for {target_url} at ref {git_ref or 'HEAD'}")

    with tempfile.TemporaryDirectory() as tmpdir:
        # Clone the repository locally
        try:
            subprocess.run(  # noqa: S603, S607
                ["git", "clone", target_url, tmpdir], check=True, capture_output=True
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

        container = DockerContainer("aquasec/trivy:latest")

        # Configure Trivy database cache using an ephemeral named volume
        container.with_env("TRIVY_CACHE_DIR", "/trivy-cache")
        container.with_volume_mapping(
            "trivy-vulnerability-db-cache", "/trivy-cache", "rw"
        )

        # Tell the container to execute the repo scan and output json for the specific commit we resolved
        container.with_command(f"repo {target_url} --commit {commit_hash} -f json")

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
