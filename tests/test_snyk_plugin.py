"""tests/test_snyk_plugin.py — Unit tests for Snyk scanner plugin."""

from unittest.mock import MagicMock, patch

from rover.plugins.snyk import (
    SnykScannerPlugin,
    parse_snyk_code_output,
    parse_snyk_oss_output,
)


def test_snyk_plugin_can_handle() -> None:
    plugin = SnykScannerPlugin()
    assert plugin.name == "snyk"
    assert plugin.can_handle("snyk")
    assert plugin.can_handle("repo")
    assert not plugin.can_handle("unknown")


def test_parse_snyk_oss_output() -> None:
    raw_json = (
        '{"vulnerabilities": [{"id": "SNYK-PYTHON-JINJA2-12345", "severity": "high"}]}'
    )
    vulns, err = parse_snyk_oss_output(raw_json)
    assert len(vulns) == 1
    assert vulns[0]["id"] == "SNYK-PYTHON-JINJA2-12345"
    assert err is None

    empty_vulns, _ = parse_snyk_oss_output("")
    assert empty_vulns == []
    invalid_vulns, _ = parse_snyk_oss_output("invalid json")
    assert invalid_vulns == []


def test_parse_snyk_code_output() -> None:
    raw_json = '{"runs": [{"results": [{"ruleId": "python/sql-injection", "level": "error"}]}]}'
    issues = parse_snyk_code_output(raw_json)
    assert len(issues) == 1
    assert issues[0]["ruleId"] == "python/sql-injection"

    assert parse_snyk_code_output("") == []
    assert parse_snyk_code_output("invalid json") == []


def test_snyk_plugin_scan_mocked() -> None:
    plugin = SnykScannerPlugin()

    mock_runner = MagicMock()
    mock_runner.return_value.stdout = "abc1234567890abcdef1234567890abcdef12345"

    mock_container = MagicMock()
    mock_container_cls = MagicMock(return_value=mock_container)
    mock_container.get_logs.return_value = (
        b'{"vulnerabilities": [{"id": "SNYK-123", "severity": "medium"}]}',
        b"",
    )

    with patch("tempfile.TemporaryDirectory") as mock_tmpdir:
        mock_tmpdir.return_value.__enter__.return_value = "/tmp/mock-snyk-dir"
        with patch(
            "rover.db.get_unmasked_secret_by_type_info",
            return_value=("test-snyk-token-123", {"id": "1"}),
        ):
            res = plugin.scan(
                target_url="https://github.com/example/repo",
                git_ref="main",
                target_type="snyk",
                container_cls=mock_container_cls,
                subprocess_runner=mock_runner,
            )

            assert res.results["snyk_oss"]["vulnerabilities"][0]["id"] == "SNYK-123"
            assert res.resolved_commit == "abc1234567890abcdef1234567890abcdef12345"
            mock_container.with_env.assert_called_with(
                "SNYK_TOKEN", "test-snyk-token-123"
            )
