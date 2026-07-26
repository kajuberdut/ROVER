"""tests/test_plugins.py — Unit tests for the scanner plugin registry and plugin classes."""

import pytest

from rover.plugins import (
    ScanResult,
    get_plugin_for_job,
    list_plugins,
    register_plugin,
)


def test_scan_result_dataclass() -> None:
    res = ScanResult(results={"foo": "bar"}, resolved_commit="abc1234", source="fresh")
    assert res.results == {"foo": "bar"}
    assert res.resolved_commit == "abc1234"
    assert res.source == "fresh"


def test_plugin_registry_lookup() -> None:
    plugins = list_plugins()
    assert len(plugins) >= 4

    trivy = get_plugin_for_job("repo")
    assert trivy.name == "trivy"
    assert trivy.can_handle("repo")
    assert trivy.can_handle("image")

    semgrep = get_plugin_for_job("semgrep")
    assert semgrep.name == "semgrep"
    assert semgrep.can_handle("semgrep")

    eol = get_plugin_for_job("major_component")
    assert eol.name == "major_component"
    assert eol.can_handle("major_component")

    helm = get_plugin_for_job("helm")
    assert helm.name == "helm"
    assert helm.can_handle("helm")


def test_missing_scanner_image_config_raises_clear_error() -> None:
    from unittest.mock import patch

    from rover import config

    with patch.object(config.settings.scanners, "trivy_image", ""):
        with pytest.raises(ValueError, match=r"\[scanners\.trivy_image\] is not set"):
            config.get_scanner_image("trivy")

    with patch.object(config.settings.scanners, "semgrep_image", None):
        with pytest.raises(ValueError, match=r"\[scanners\.semgrep_image\] is not set"):
            config.get_scanner_image("semgrep")


def test_get_plugin_for_job_unknown() -> None:
    with pytest.raises(
        ValueError, match="No scanner plugin registered for target_type"
    ):
        get_plugin_for_job("unknown_target_type")


class CustomTestPlugin:
    name = "custom"
    supported_asset_types = {"custom_type"}

    def can_handle(self, target_type: str) -> bool:
        return target_type == "custom_type"

    def scan(
        self,
        target_url: str,
        git_ref: str | None = None,
        target_type: str = "repo",
    ) -> ScanResult:
        return ScanResult(results={"custom": True})


def test_register_custom_plugin() -> None:
    custom = CustomTestPlugin()
    register_plugin(custom)  # type: ignore[arg-type]

    found = get_plugin_for_job("custom_type")
    assert found.name == "custom"
    res = found.scan("http://example.com")
    assert res.results == {"custom": True}
