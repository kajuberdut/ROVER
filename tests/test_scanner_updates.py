"""tests/test_scanner_updates.py — Unit tests for start-time check of upstream scanner updates."""

from unittest.mock import MagicMock, patch

from rover import db
from rover.scanner_updates import (
    check_scanner_updates,
    check_scanner_updates_at_startup,
    extract_version_from_image_ref,
    fetch_latest_upstream_release,
    is_newer_version,
    parse_semver_tuple,
)


def test_extract_version_from_image_ref() -> None:
    assert extract_version_from_image_ref("aquasec/trivy:0.72.0") == "0.72.0"
    assert extract_version_from_image_ref("semgrep/semgrep:v1.15.0") == "1.15.0"
    assert (
        extract_version_from_image_ref("aquasec/trivy:0.72.0@sha256:abc12345")
        == "0.72.0"
    )
    assert (
        extract_version_from_image_ref(
            "aquasec/trivy@sha256:abc12345", fallback_version="0.72.0"
        )
        == "0.72.0"
    )
    assert extract_version_from_image_ref(None, fallback_version="1.15.0") == "1.15.0"


def test_semver_parsing_and_comparison() -> None:
    assert parse_semver_tuple("0.72.0") == (0, 72, 0)
    assert parse_semver_tuple("v1.16.2") == (1, 16, 2)
    assert parse_semver_tuple("invalid") == (0, 0, 0)

    assert is_newer_version("0.74.0", "0.72.0") is True
    assert is_newer_version("1.16.0", "1.15.0") is True
    assert is_newer_version("1.15.0", "1.15.0") is False
    assert is_newer_version("0.70.0", "0.72.0") is False


def test_fetch_latest_upstream_release_success() -> None:
    mock_response = MagicMock()
    mock_response.read.return_value = b'{"tag_name": "v0.74.0"}'

    def mock_opener(req, timeout=5):
        return mock_response

    ver = fetch_latest_upstream_release("aquasecurity/trivy", url_opener=mock_opener)
    assert ver == "0.74.0"


def test_fetch_latest_upstream_release_error() -> None:
    def mock_failing_opener(req, timeout=5):
        raise TimeoutError("Connection timed out")

    ver = fetch_latest_upstream_release(
        "aquasecurity/trivy", url_opener=mock_failing_opener
    )
    assert ver is None


def test_check_scanner_updates_integration() -> None:
    mock_settings = MagicMock()
    mock_settings.scanners.trivy_image = "aquasec/trivy:0.72.0"
    mock_settings.scanners.semgrep_image = "semgrep/semgrep:1.15.0"
    mock_settings.scanners.snyk_image = "snyk/snyk:alpine@sha256:12345"
    mock_settings.scanners.helm_image = "alpine/helm:3.16.2"

    releases_map = {
        "aquasecurity/trivy": "0.74.0",
        "semgrep/semgrep": "1.16.0",
        "snyk/cli": "1.1290.0",
        "helm/helm": "3.16.2",
    }

    def mock_fetch(repo_slug, timeout=5, url_opener=None):
        return releases_map.get(repo_slug)

    with patch(
        "rover.scanner_updates.fetch_latest_upstream_release", side_effect=mock_fetch
    ):
        created = check_scanner_updates(settings_obj=mock_settings)

    # Trivy and Semgrep should have update notifications created (0.74.0 > 0.72.0 and 1.16.0 > 1.15.0)
    # Snyk (1.1290.0 == 1.1290.0) and Helm (3.16.2 == 3.16.2) are up to date.
    assert len(created) == 2
    tools = [c["source_tool"] for c in created]
    assert "trivy" in tools
    assert "semgrep" in tools

    active_notifs = db.get_active_admin_notifications()
    trivy_notif = next((n for n in active_notifs if n["source_tool"] == "trivy"), None)
    assert trivy_notif is not None
    assert trivy_notif["category"] == "scanner_update"
    assert "v0.74.0" in trivy_notif["title"]
    assert trivy_notif["metadata"]["available_version"] == "0.74.0"

    semgrep_notif = next(
        (n for n in active_notifs if n["source_tool"] == "semgrep"), None
    )
    assert semgrep_notif is not None
    assert semgrep_notif["category"] == "scanner_update"
    assert "v1.16.0" in semgrep_notif["title"]
    assert semgrep_notif["metadata"]["available_version"] == "1.16.0"

    # Deduplication test: re-running should not create duplicate notifications
    with patch(
        "rover.scanner_updates.fetch_latest_upstream_release", side_effect=mock_fetch
    ):
        created_dup = check_scanner_updates(settings_obj=mock_settings)
    assert len(created_dup) == 0


def test_check_scanner_updates_at_startup_handles_exception() -> None:
    with (
        patch("os.getenv", return_value=None),
        patch(
            "rover.scanner_updates.check_scanner_updates",
            side_effect=RuntimeError("Network error"),
        ),
    ):
        # Should not raise exception
        check_scanner_updates_at_startup()
