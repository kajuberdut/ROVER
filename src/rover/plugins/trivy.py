"""src/rover/plugins/trivy.py — Trivy scanner plugin for dependency and container image CVE scans."""

import json
import logging
import re
import subprocess
import tempfile
from typing import Any, cast

# ruff: noqa: S603, S607
from testcontainers.core.container import DockerContainer  # type: ignore

from rover import vault
from rover.plugins.base import ScanResult

logger = logging.getLogger(__name__)


def _check_and_raise_trivy_notices(stdout: str, stderr: str) -> None:
    """Parses Trivy output logs for update notices and records admin notifications."""
    combined_logs = f"{stdout}\n{stderr}"

    match = re.search(
        r"Version\s+([vV]?\d+\.\d+\.\d+)\s+of\s+Trivy\s+is\s+now\s+available,\s+current\s+version\s+is\s+([vV]?\d+\.\d+\.\d+)",
        combined_logs,
        re.IGNORECASE,
    )
    if match:
        available_version = match.group(1)
        current_version = match.group(2)

        try:
            from rover import db

            title = f"Trivy Scanner Update Available (v{available_version})"
            message = (
                f"Version {available_version} of Trivy is now available. "
                f"The current version running in ROVER is {current_version}."
            )
            db.create_admin_notification(
                title=title,
                message=message,
                category="scanner_update",
                source_tool="trivy",
                metadata_dict={
                    "current_version": current_version,
                    "available_version": available_version,
                },
            )
            logger.info(
                f"Recorded admin notification for Trivy update: v{current_version} -> v{available_version}"
            )
        except Exception as e:
            logger.warning(f"Failed to record Trivy update notification: {e}")


def resolve_image_hash(
    image_name: str, subprocess_runner: Any | None = None
) -> str | None:
    """Resolves container image digest (e.g., sha256:...) using Skopeo or Docker Registry API."""
    logger.info(f"Resolving image hash for {image_name}")
    runner = subprocess_runner or subprocess.run

    # Attempt 1: Skopeo inspect if available
    try:
        url = f"docker://{image_name}"
        res = runner(
            ["skopeo", "inspect", url],
            capture_output=True,
            text=True,
            timeout=15,
            check=True,
        )
        data = json.loads(res.stdout)
        digest = data.get("Digest")
        if digest:
            return str(digest)
    except Exception as e:
        logger.debug(f"Skopeo inspect skipped or failed for {image_name}: {e}")

    # Attempt 2: Direct Docker Registry v2 API query via urllib
    try:
        import urllib.request

        repo = image_name.split(":")[0]
        tag = image_name.split(":")[1] if ":" in image_name else "latest"
        if "/" not in repo:
            repo = f"library/{repo}"

        auth_url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull"
        req = urllib.request.Request(auth_url)  # noqa: S310
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            token = json.loads(resp.read().decode())["token"]

        manifest_url = f"https://registry-1.docker.io/v2/{repo}/manifests/{tag}"
        req = urllib.request.Request(  # noqa: S310
            manifest_url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.index.v1+json",
            },
        )
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            digest = resp.headers.get("Docker-Content-Digest")

            if digest:
                logger.info(
                    f"Resolved image digest via Docker Registry API for {image_name}: {digest}"
                )
                return str(digest)
    except Exception as e:
        logger.warning(f"Docker Registry API lookup failed for {image_name}: {e}")

    return None


class TrivyScannerPlugin:
    """Scanner plugin that executes Trivy dependency and container image CVE scans."""

    name = "trivy"
    display_name = "Trivy Scanner"
    icon = "🛡️"
    description = "Trivy Dependency and Container Image Vulnerability Scanner (CVEs)"
    template_name: str | None = "report_trivy.html"
    supported_asset_types = {"trivy", "repo", "image"}

    def can_handle(self, target_type: str) -> bool:
        return target_type in self.supported_asset_types

    def get_badge_info(
        self,
        results: dict[str, Any] | None,
        status: str | None,
        error_message: str | None = None,
        duration_seconds: int | None = None,
        avg_duration_seconds: int | None = None,
    ) -> dict[str, Any]:
        duration_str = (
            f"{duration_seconds}s"
            if (duration_seconds is not None and duration_seconds < 60)
            else (
                f"{duration_seconds // 60}m {duration_seconds % 60:02d}s"
                if duration_seconds is not None
                else None
            )
        )
        avg_str = (
            f"{int(avg_duration_seconds)}s"
            if (avg_duration_seconds is not None and avg_duration_seconds < 60)
            else (
                f"{int(avg_duration_seconds) // 60}m {int(avg_duration_seconds) % 60:02d}s"
                if avg_duration_seconds is not None
                else None
            )
        )

        time_label = ""
        if status == "running" and duration_str:
            time_label = f" ({duration_str}" + (f", avg {avg_str})" if avg_str else ")")
        elif status == "queued" and avg_str:
            time_label = f" (avg {avg_str})"
        elif status == "completed" and duration_str:
            time_label = f" [{duration_str}]"

        if status == "failed":
            return {
                "label": f"🛡️ ⚠️ Trivy Failed{time_label}",
                "status": "failed",
                "bg": "#d32f2f",
                "border": "#b71c1c",
                "color": "white",
                "tooltip": f"Trivy Scan Failed: {error_message or 'Execution error'}",
                "duration_str": duration_str,
                "avg_str": avg_str,
            }
        if status in ("queued", "running"):
            return {
                "label": f"🛡️ ⏳ Trivy {status}{time_label}",
                "status": status,
                "bg": "#ff9800",
                "border": "#e65100",
                "color": "white",
                "busy": True,
                "duration_str": duration_str,
                "avg_str": avg_str,
            }
        if results:
            critical = 0
            high = 0
            medium = 0
            low = 0
            for r in results.get("Results", []) or []:
                for v in r.get("Vulnerabilities", []) or []:
                    sev = str(v.get("Severity", "")).upper()
                    if sev == "CRITICAL":
                        critical += 1
                    elif sev == "HIGH":
                        high += 1
                    elif sev == "MEDIUM":
                        medium += 1
                    elif sev == "LOW":
                        low += 1
            total = critical + high + medium + low
            if total > 0:
                return {
                    "label": f"🛡️ {total} CVEs{time_label}",
                    "status": "has_vulns",
                    "critical": critical,
                    "high": high,
                    "medium": medium,
                    "low": low,
                    "total": total,
                    "bg": "#d32f2f"
                    if critical > 0
                    else ("#f57c00" if high > 0 else "#fbc02d"),
                    "border": "#b71c1c"
                    if critical > 0
                    else ("#e65100" if high > 0 else "#f57f17"),
                    "color": "white" if (critical > 0 or high > 0) else "#333",
                    "duration_str": duration_str,
                    "avg_str": avg_str,
                }
            return {
                "label": f"🛡️ CVE Clean{time_label}",
                "status": "clean",
                "bg": "transparent",
                "border": "#388e3c",
                "color": "#388e3c",
                "duration_str": duration_str,
                "avg_str": avg_str,
            }
        return {
            "label": "🛡️ No CVE Data",
            "status": "none",
            "duration_str": duration_str,
            "avg_str": avg_str,
        }

    def scan(
        self,
        target_url: str,
        git_ref: str | None = None,
        target_type: str = "repo",
        container_cls: Any | None = None,
        subprocess_runner: Any | None = None,
    ) -> ScanResult:
        logger.info(
            f"Starting Trivy scan for {target_type} {target_url} (ref {git_ref or 'HEAD'})"
        )
        runner = subprocess_runner or subprocess.run
        dock_cls = container_cls or DockerContainer

        with tempfile.TemporaryDirectory() as tmpdir:
            commit_hash = "latest"
            tags_str = None

            if target_type == "repo":
                import os

                auth_url = vault.get_authenticated_git_url(target_url)
                env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
                try:
                    runner(
                        ["git", "clone", auth_url, tmpdir],
                        check=True,
                        capture_output=True,
                        env=env,
                    )

                except subprocess.CalledProcessError as e:
                    err_msg = (
                        e.stderr.decode("utf-8")
                        if isinstance(e.stderr, bytes)
                        else str(e.stderr)
                    )
                    logger.error(f"Failed to clone repository: {err_msg}")
                    raise Exception("Failed to clone target repository")

                if git_ref:
                    try:
                        runner(
                            ["git", "checkout", git_ref],
                            cwd=tmpdir,
                            check=True,
                            capture_output=True,
                        )
                    except subprocess.CalledProcessError as e:
                        err_msg = (
                            e.stderr.decode("utf-8")
                            if isinstance(e.stderr, bytes)
                            else str(e.stderr)
                        )
                        logger.error(f"Failed to checkout ref {git_ref}: {err_msg}")
                        raise Exception(f"Failed to checkout git reference: {git_ref}")

                try:
                    res = runner(
                        ["git", "rev-parse", "HEAD"],
                        cwd=tmpdir,
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                    commit_hash = res.stdout.strip()

                    res = runner(
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
                image_target = target_url
                if git_ref and ":" not in image_target.split("/")[-1]:
                    image_target = f"{target_url}:{git_ref}"
                tags_str = image_target
            from rover import config

            trivy_img = config.get_scanner_image("trivy")
            container = dock_cls(trivy_img)

            container.with_env("TRIVY_CACHE_DIR", "/trivy-cache")
            container.with_volume_mapping(
                "trivy-vulnerability-db-cache", "/trivy-cache", "rw"
            )
            container.with_volume_mapping(
                "/var/run/docker.sock", "/var/run/docker.sock", "ro"
            )

            if target_type == "repo":
                container.with_volume_mapping(tmpdir, "/src", "ro")
                container.with_command("fs /src -f json")
            else:
                container.with_command(f"image {image_target} -f json")

            try:
                container.start()

                client = container.get_docker_client()
                result = client.client.containers.get(
                    container.get_wrapped_container().id
                )

                exit_code = result.wait()["StatusCode"]

                logs = container.get_logs()
                stdout = logs[0].decode("utf-8")
                stderr = logs[1].decode("utf-8")

                logger.info(f"Trivy stdout (first 200 chars): {stdout[:200]}")
                logger.info(f"Trivy stderr: {stderr}")

                _check_and_raise_trivy_notices(stdout, stderr)

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

                    return ScanResult(
                        results=scan_results,
                        resolved_commit=commit_hash,
                        resolved_tags=tags_str,
                        source="fresh",
                    )

                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse Trivy JSON output. Error: {e}")
                    logger.error(f"Raw output: {stdout}")
                    raise Exception("Failed to parse vulnerability report")

            finally:
                container.stop()
