"""src/rover/plugins/helm.py — Helm chart interrogation and rendering scanner plugin."""

import json
import logging
from typing import Any

import docker  # type: ignore[import-untyped]

# ruff: noqa: S603, S607
from testcontainers.core.container import DockerContainer  # type: ignore

from rover import config
from rover.plugins.base import ScanResult

logger = logging.getLogger(__name__)


def _get_helm_image() -> str:
    return config.get_scanner_image("helm")


def fetch_helm_chart_versions(repo_url: str) -> dict[str, list[str]]:
    """Spawns an ephemeral alpine/helm container to interrogate a remote Helm repository.

    Returns a dictionary mapping chart names to a list of available versions.
    """
    docker_client = docker.from_env()
    logger.info(f"Interrogating helm repo {repo_url} for charts and versions")

    is_oci = repo_url.startswith("oci://")

    try:
        if is_oci:
            return _fetch_oci_chart_versions(docker_client, repo_url)
        else:
            return _fetch_http_repo_versions(docker_client, repo_url)
    except Exception as e:
        logger.error(f"Failed to fetch helm chart versions for {repo_url}: {e}")
        return {}


def _fetch_oci_chart_versions(docker_client: Any, oci_url: str) -> dict[str, list[str]]:
    import yaml  # type: ignore[import-untyped]

    client = docker_client
    logger.info(f"Using OCI path for {oci_url}")

    output_bytes = client.containers.run(
        _get_helm_image(),
        command=["-c", f"helm show chart {oci_url} 2>&1"],
        entrypoint="sh",
        remove=True,
        stdout=True,
        stderr=False,
    )
    output = output_bytes.decode("utf-8")

    yaml_start = output.find("apiVersion:")
    if yaml_start == -1:
        yaml_start = output.find("annotations:")
    if yaml_start == -1:
        yaml_start = 0

    chart_data = yaml.safe_load(output[yaml_start:])
    chart_name = chart_data.get("name") or oci_url.rstrip("/").split("/")[-1]
    version = chart_data.get("version", "latest")
    return {chart_name: [version]}


def _fetch_http_repo_versions(
    docker_client: Any, repo_url: str
) -> dict[str, list[str]]:
    output_bytes = docker_client.containers.run(
        _get_helm_image(),
        command=[
            "-c",
            f"helm repo add temp {repo_url} > /dev/null 2>&1 && helm search repo temp -l -o json",
        ],
        entrypoint="sh",
        remove=True,
        stdout=True,
        stderr=False,
    )

    output_json = output_bytes.decode("utf-8")

    json_start = output_json.find("[")
    if json_start != -1:
        output_json = output_json[json_start:]

    raw_data = json.loads(output_json)

    chart_catalog: dict[str, list[str]] = {}
    for entry in raw_data:
        raw_name = entry.get("name", "")
        chart_name = raw_name[5:] if raw_name.startswith("temp/") else raw_name
        version = entry.get("version")
        if chart_name and version:
            if chart_name not in chart_catalog:
                chart_catalog[chart_name] = []
            chart_catalog[chart_name].append(version)
    return chart_catalog


def run_helm_ingestion(
    repo_url: str,
    chart_name: str,
    chart_version: str | None = None,
    container_cls: Any | None = None,
) -> list[str]:
    """Renders a Helm chart using an ephemeral alpine/helm container and extracts all container images."""
    import yaml  # type: ignore[import-untyped]

    logger.info(
        f"Starting Helm ingestion for {repo_url} / {chart_name} (version: {chart_version or 'latest'})"
    )

    is_oci = repo_url.startswith("oci://")
    if is_oci:
        cmd = f"template {chart_name} {repo_url}"
        if chart_version:
            cmd += f" --version {chart_version}"
    else:
        cmd = f"template {chart_name} {chart_name} --repo {repo_url}"
        if chart_version:
            cmd += f" --version {chart_version}"

    dock_cls = container_cls or DockerContainer
    container = dock_cls(_get_helm_image()).with_command(cmd)

    try:
        container.start()

        client = container.get_docker_client()
        result = client.client.containers.get(container.get_wrapped_container().id)
        exit_code = result.wait()["StatusCode"]

        logs = container.get_logs()
        stdout = logs[0].decode("utf-8")
        stderr = logs[1].decode("utf-8")

        if exit_code != 0:
            logger.error(
                f"Helm template failed with code {exit_code}. Stderr: {stderr}"
            )
            raise Exception(f"Failed to ingest helm chart: {stderr}")

        images = set()
        docs = yaml.safe_load_all(stdout)

        def find_images(obj: Any) -> None:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k == "image" and isinstance(v, str):
                        images.add(v)
                    else:
                        find_images(v)
            elif isinstance(obj, list):
                for item in obj:
                    find_images(item)

        for doc in docs:
            if doc:
                find_images(doc)

        logger.info(f"Successfully extracted {len(images)} images from Helm chart")
        return list(images)

    except Exception as e:
        logger.error(f"Error during helm ingestion: {e}")
        raise
    finally:
        container.stop()


class HelmScannerPlugin:
    """Scanner plugin that handles Helm chart interrogation and template ingestion."""

    name: str = "helm"
    supported_asset_types: set[str] = {"helm"}

    def can_handle(self, target_type: str) -> bool:
        return target_type in self.supported_asset_types

    def scan(
        self,
        target_url: str,
        git_ref: str | None = None,
        target_type: str = "helm",
    ) -> ScanResult:
        images = run_helm_ingestion(target_url, chart_name=git_ref or "")
        return ScanResult(results={"images": images}, source="fresh")
