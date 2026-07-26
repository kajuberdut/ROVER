"""src/rover/plugins/semgrep.py — Semgrep SAST scanner plugin."""

import json
import logging
import re
import uuid
from typing import Any, cast

import docker  # type: ignore[import-untyped]
from testcontainers.core.container import DockerContainer  # type: ignore

from rover import vault
from rover.plugins.base import ScanResult

logger = logging.getLogger(__name__)


class SemgrepScannerPlugin:
    """Scanner plugin that executes Semgrep SAST scans using ephemeral Docker volumes."""

    name: str = "semgrep"
    supported_asset_types: set[str] = {"semgrep"}

    def can_handle(self, target_type: str) -> bool:
        return target_type in self.supported_asset_types

    def scan(
        self,
        target_url: str,
        git_ref: str | None = None,
        target_type: str = "semgrep",
        container_cls: Any | None = None,
    ) -> ScanResult:
        logger.info(
            f"Starting Semgrep scan for repo {target_url} (ref {git_ref or 'HEAD'})"
        )
        dock_cls = container_cls or DockerContainer

        docker_client = docker.from_env()
        volume_name = f"rover-semgrep-clone-{uuid.uuid4().hex[:12]}"

        try:
            docker_client.volumes.create(name=volume_name)
            logger.info(f"Created Docker volume {volume_name} for semgrep clone")

            is_commit = bool(git_ref and re.fullmatch(r"[0-9a-f]{7,40}", git_ref))

            auth_url = vault.get_authenticated_git_url(target_url)

            if is_commit:
                clone_args = ["clone", auth_url, "/src"]
            elif git_ref:
                clone_args = [
                    "clone",
                    "--branch",
                    git_ref,
                    "--depth",
                    "1",
                    auth_url,
                    "/src",
                ]
            else:
                clone_args = ["clone", "--depth", "1", auth_url, "/src"]

            docker_client.containers.run(
                "alpine/git",
                command=clone_args,
                volumes={volume_name: {"bind": "/src", "mode": "rw"}},
                remove=True,
                stdout=True,
                stderr=True,
            )

            if is_commit:
                docker_client.containers.run(
                    "alpine/git",
                    command=["-C", "/src", "checkout", git_ref],
                    volumes={volume_name: {"bind": "/src", "mode": "rw"}},
                    remove=True,
                    stdout=True,
                    stderr=True,
                )
                logger.info(f"Checked out commit {git_ref} in volume {volume_name}")

            logger.info(
                f"Cloned {target_url} (ref={git_ref or 'default'}) into volume {volume_name}"
            )

            commit_hash = "unknown"
            tags_str = None
            try:
                rev = docker_client.containers.run(
                    "alpine/git",
                    command=["-C", "/src", "rev-parse", "HEAD"],
                    volumes={volume_name: {"bind": "/src", "mode": "ro"}},
                    remove=True,
                    stdout=True,
                    stderr=False,
                )
                commit_hash = rev.decode("utf-8").strip()

                tag_out = docker_client.containers.run(
                    "alpine/git",
                    command=["-C", "/src", "tag", "--points-at", "HEAD"],
                    volumes={volume_name: {"bind": "/src", "mode": "ro"}},
                    remove=True,
                    stdout=True,
                    stderr=False,
                )
                tags = [
                    t.strip() for t in tag_out.decode("utf-8").split("\n") if t.strip()
                ]
                tags_str = ", ".join(tags) if tags else None
            except Exception as e:
                logger.warning(f"Failed to capture git metadata: {e}")

            from rover import config

            semgrep_img = config.get_scanner_image("semgrep")
            container = dock_cls(semgrep_img)

            container.with_volume_mapping(volume_name, "/src", "ro")
            container.with_command(
                "semgrep scan /src --json --no-git-ignore --config auto"
            )

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

                logger.info(f"Semgrep stdout (first 200 chars): {stdout[:200]}")
                logger.info(f"Semgrep stderr: {stderr[:500]}")

                if exit_code not in (0, 1):
                    logger.warning(
                        f"Semgrep scan exited with code {exit_code}. Stderr: {stderr}"
                    )

                try:
                    json_start = stdout.find("{")
                    json_end = stdout.rfind("}") + 1
                    if json_start >= 0 and json_end > json_start:
                        scan_results = cast(
                            dict[str, Any], json.loads(stdout[json_start:json_end])
                        )
                    else:
                        if exit_code not in (0, 1):
                            raise Exception(
                                f"Semgrep failed with exit code {exit_code}"
                            )
                        scan_results = {"results": [], "errors": []}

                    return ScanResult(
                        results=scan_results,
                        resolved_commit=commit_hash,
                        resolved_tags=tags_str,
                        source="fresh",
                    )

                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse Semgrep JSON output. Error: {e}")
                    logger.error(f"Raw output: {stdout[:500]}")
                    raise Exception("Failed to parse Semgrep report")

            finally:
                container.stop()

        finally:
            try:
                vol = docker_client.volumes.get(volume_name)
                vol.remove(force=True)
                logger.info(f"Removed Docker volume {volume_name}")
            except Exception as e:
                logger.warning(f"Failed to remove volume {volume_name}: {e}")
