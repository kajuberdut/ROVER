"""src/rover/scanner_updates.py — Start-time checking for upstream scanner image updates."""

import json
import logging
import re
import urllib.error
import urllib.request
from typing import Any

from rover import config, db

logger = logging.getLogger(__name__)

# Upstream GitHub repository mappings for ROVER scanner tools
SCANNER_UPSTREAM_MAP: dict[str, dict[str, str]] = {
    "trivy": {
        "repo": "aquasecurity/trivy",
        "display_name": "Trivy",
        "fallback_version": "0.72.0",
    },
    "semgrep": {
        "repo": "semgrep/semgrep",
        "display_name": "Semgrep",
        "fallback_version": "1.15.0",
    },
    "snyk": {
        "repo": "snyk/cli",
        "display_name": "Snyk",
        "fallback_version": "1.1290.0",
    },
    "helm": {
        "repo": "helm/helm",
        "display_name": "Helm",
        "fallback_version": "3.16.2",
    },
}


def extract_version_from_image_ref(
    image_ref: str | None, fallback_version: str | None = None
) -> str | None:
    """Extracts a semantic version string (e.g., '0.72.0' or '1.15.0') from a container image ref.

    If no semver tag is present in the image ref string (e.g. pinned by digest only),
    returns `fallback_version` if specified.
    """
    if not image_ref:
        return fallback_version

    # Match semver pattern v?X.Y.Z
    match = re.search(r"v?(\d+\.\d+\.\d+)", image_ref)
    if match:
        return match.group(1)

    return fallback_version


def parse_semver_tuple(v_str: str) -> tuple[int, int, int]:
    """Parses a semver string into an integer tuple (major, minor, patch)."""
    cleaned = re.sub(r"^[vV]", "", v_str.strip())
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", cleaned)
    if match:
        return (int(match.group(1)), int(match.group(2)), int(match.group(3)))
    return (0, 0, 0)


def is_newer_version(available_version: str, current_version: str) -> bool:
    """Returns True if `available_version` is strictly greater than `current_version`."""
    av_tuple = parse_semver_tuple(available_version)
    curr_tuple = parse_semver_tuple(current_version)
    return av_tuple > curr_tuple and av_tuple != (0, 0, 0)


def fetch_latest_upstream_release(
    repo_slug: str,
    timeout: int = 5,
    url_opener: Any = None,
) -> str | None:
    """Queries the GitHub Releases API for the latest release tag of an upstream repository.

    Returns the clean version string (e.g., '0.74.0'), or None if unreachable or rate-limited.
    """
    url = f"https://api.github.com/repos/{repo_slug}/releases/latest"
    opener = url_opener or urllib.request.urlopen
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "ROVER-Scanner-Update-Checker",
            "Accept": "application/vnd.github+json",
        },
    )

    try:
        response = opener(req, timeout=timeout)
        if hasattr(response, "read"):
            data = json.loads(response.read().decode("utf-8"))
        else:
            data = response
        tag_name = data.get("tag_name", "")
        if tag_name:
            match = re.search(r"v?(\d+\.\d+\.\d+)", tag_name)
            if match:
                return match.group(1)
    except Exception as err:
        logger.debug(f"Could not fetch latest release for '{repo_slug}': {err}")

    return None


def check_scanner_updates(
    settings_obj: Any | None = None,
    url_opener: Any = None,
) -> list[dict[str, Any]]:
    """Inspects configured scanner images against upstream releases and records admin notifications for updates.

    Returns a list of created admin notification summaries.
    """
    active_settings = settings_obj or config.settings
    notifications_created = []

    for tool_key, info in SCANNER_UPSTREAM_MAP.items():
        image_attr = f"{tool_key}_image"
        configured_image = getattr(active_settings.scanners, image_attr, None)

        current_ver = extract_version_from_image_ref(
            configured_image, fallback_version=info["fallback_version"]
        )
        if not current_ver:
            continue

        available_ver = fetch_latest_upstream_release(
            info["repo"], timeout=5, url_opener=url_opener
        )

        if available_ver and is_newer_version(available_ver, current_ver):
            title = (
                f"{info['display_name']} Scanner Update Available (v{available_ver})"
            )
            message = (
                f"Version {available_ver} of {info['display_name']} is now available. "
                f"The current version running in ROVER is {current_ver}."
            )
            notif_id = db.create_admin_notification(
                title=title,
                message=message,
                category="scanner_update",
                source_tool=tool_key,
                metadata_dict={
                    "current_version": current_ver,
                    "available_version": available_ver,
                },
            )
            if notif_id:
                logger.info(
                    f"Recorded admin notification for {info['display_name']} update: v{current_ver} -> v{available_ver}"
                )
                notifications_created.append(
                    {
                        "id": notif_id,
                        "source_tool": tool_key,
                        "current_version": current_ver,
                        "available_version": available_ver,
                    }
                )
        else:
            db.dismiss_outdated_scanner_notifications(tool_key, current_ver)

    return notifications_created


def check_scanner_updates_at_startup() -> None:
    """Safe startup wrapper that checks for scanner updates and logs any failures without interrupting startup."""
    import os

    if os.getenv("PYTEST_CURRENT_TEST") or os.getenv("ROVER_SKIP_STARTUP_CHECKS"):
        logger.debug("Skipping startup scanner update check under test environment.")
        return

    try:
        created = check_scanner_updates()
        if created:
            logger.info(
                f"Startup scanner update check completed: {len(created)} update notification(s) queued."
            )
        else:
            logger.info(
                "Startup scanner update check completed: all scanner images are up-to-date."
            )
    except Exception as exc:
        logger.warning(f"Failed to complete startup check for scanner updates: {exc}")
