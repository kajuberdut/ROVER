"""src/rover/scanner.py — Backward-compatible facade for scanner plugins.

Delegates scan execution to the scanner plugins in ``rover.plugins``.
Preserves module-level symbols and function signatures for unit test compatibility.
"""

import logging
import subprocess
import urllib.error
import urllib.request
from typing import Any

# ruff: noqa: S603, S607
from testcontainers.core.container import DockerContainer  # type: ignore # noqa: F401

from rover import db  # noqa: F401
from rover.plugins.eol import EolComponentScannerPlugin
from rover.plugins.helm import fetch_helm_chart_versions as _fetch_helm_versions
from rover.plugins.helm import run_helm_ingestion as _run_helm_ingest
from rover.plugins.semgrep import SemgrepScannerPlugin
from rover.plugins.trivy import TrivyScannerPlugin
from rover.plugins.trivy import resolve_image_hash as _resolve_hash

logger = logging.getLogger(__name__)


def run_major_component_scan(
    target_name: str, target_version: str
) -> tuple[dict[str, Any], str, str | None]:
    """Fetches the end of life date for a given component and version.

    Utilizes a 28-day database cache to avoid rate limiting.
    """
    plugin = EolComponentScannerPlugin()
    res = plugin.scan(
        target_url=target_name,
        git_ref=target_version,
        target_type="major_component",
        db_module=db,
        url_opener=urllib.request.urlopen,
    )
    return res.results, res.source, res.status


def resolve_image_hash(image_name: str) -> str | None:
    """Uses skopeo inspect to pull the image digest (e.g., sha256:...)."""
    return _resolve_hash(image_name, subprocess_runner=subprocess.run)


def run_trivy_scan(
    target_url: str, git_ref: str | None = None, target_type: str = "repo"
) -> tuple[dict[str, Any], str, str | None]:
    """Runs a Trivy CVE scan against a git repository or Docker image using Testcontainers."""
    plugin = TrivyScannerPlugin()
    res = plugin.scan(
        target_url=target_url,
        git_ref=git_ref,
        target_type=target_type,
        container_cls=DockerContainer,
        subprocess_runner=subprocess.run,
    )
    return (
        res.results,
        res.resolved_commit or "latest",
        res.resolved_tags,
    )


def run_semgrep_scan(
    target_url: str, git_ref: str | None = None
) -> tuple[dict[str, Any], str, str | None]:
    """Runs a Semgrep SAST scan against a cloned git repository using Testcontainers."""
    plugin = SemgrepScannerPlugin()
    res = plugin.scan(
        target_url=target_url,
        git_ref=git_ref,
        target_type="semgrep",
        container_cls=DockerContainer,
    )
    return (
        res.results,
        res.resolved_commit or "unknown",
        res.resolved_tags,
    )


def fetch_helm_chart_versions(repo_url: str) -> dict[str, list[str]]:
    """Interrogates a remote Helm repository for charts and available versions."""
    return _fetch_helm_versions(repo_url)


def run_helm_ingestion(
    repo_url: str, chart_name: str, chart_version: str | None = None
) -> list[str]:
    """Renders a Helm chart using an ephemeral container and extracts container images."""
    return _run_helm_ingest(
        repo_url=repo_url,
        chart_name=chart_name,
        chart_version=chart_version,
        container_cls=DockerContainer,
    )


__all__ = [
    "DockerContainer",
    "db",
    "fetch_helm_chart_versions",
    "resolve_image_hash",
    "run_helm_ingestion",
    "run_major_component_scan",
    "run_semgrep_scan",
    "run_trivy_scan",
    "subprocess",
    "urllib",
]
