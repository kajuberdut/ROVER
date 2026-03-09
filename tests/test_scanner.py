import json
from subprocess import CalledProcessError
from unittest.mock import MagicMock, patch

import pytest

from rover.scanner import run_major_component_scan, run_semgrep_scan, run_trivy_scan


def _mock_subprocess_run(cmd, *args, **kwargs):
    # Depending on the command, return appropriate mocked output
    mock_res = MagicMock()
    if cmd[:2] == ["git", "rev-parse"]:
        mock_res.stdout = "mocked_hash\n"
    elif cmd[:2] == ["git", "tag"]:
        mock_res.stdout = "v1.0\n"
    elif cmd[0] == "git":
        mock_res.stdout = ""
    return mock_res


@patch("rover.scanner.subprocess.run")
def test_run_trivy_scan_success(mock_run):
    mock_run.side_effect = _mock_subprocess_run
    mock_json = (
        '{"Vulnerabilities": [{"VulnerabilityID": "CVE-123", "Severity": "CRITICAL"}]}'
    )

    with patch("rover.scanner.DockerContainer") as MockDockerContainer:
        mock_container_instance = MagicMock()
        MockDockerContainer.return_value = mock_container_instance

        # Mock get_docker_client to return a client that returns an exit code of 0
        mock_client = MagicMock()
        mock_client.client.containers.get.return_value.wait.return_value = {
            "StatusCode": 0
        }
        mock_container_instance.get_docker_client.return_value = mock_client

        # Mock get_logs to return our JSON fixture
        mock_container_instance.get_logs.return_value = (mock_json.encode("utf-8"), b"")

        results, commit_hash, tags_str = run_trivy_scan(
            "https://github.com/pallets/flask"
        )

        assert "Vulnerabilities" in results
        assert results["Vulnerabilities"][0]["VulnerabilityID"] == "CVE-123"
        assert commit_hash == "mocked_hash"
        assert tags_str == "v1.0"

        # Verify container was started and stopped
        mock_container_instance.start.assert_called_once()
        mock_container_instance.stop.assert_called_once()


@patch("rover.scanner.subprocess.run")
def test_run_trivy_scan_no_json(mock_run):
    mock_run.side_effect = _mock_subprocess_run
    mock_log = "Information logs without any json..."

    with patch("rover.scanner.DockerContainer") as MockDockerContainer:
        mock_container_instance = MagicMock()
        MockDockerContainer.return_value = mock_container_instance

        # Mock client exiting with 0
        mock_client = MagicMock()
        mock_client.client.containers.get.return_value.wait.return_value = {
            "StatusCode": 0
        }
        mock_container_instance.get_docker_client.return_value = mock_client

        # Mock logs
        mock_container_instance.get_logs.return_value = (mock_log.encode("utf-8"), b"")

        results, commit_hash, tags_str = run_trivy_scan("https://example.com/repo")

        assert results == {"Results": []}
        assert commit_hash == "mocked_hash"
        assert tags_str == "v1.0"


@patch("rover.scanner.subprocess.run")
def test_run_trivy_scan_invalid_json(mock_run):
    mock_run.side_effect = _mock_subprocess_run
    mock_invalid_json = '{"Results": [broken]}'

    with patch("rover.scanner.DockerContainer") as MockDockerContainer:
        mock_container_instance = MagicMock()
        MockDockerContainer.return_value = mock_container_instance

        # Mock client
        mock_client = MagicMock()
        mock_client.client.containers.get.return_value.wait.return_value = {
            "StatusCode": 0
        }
        mock_container_instance.get_docker_client.return_value = mock_client

        # Mock logs
        mock_container_instance.get_logs.return_value = (
            mock_invalid_json.encode("utf-8"),
            b"",
        )

        with pytest.raises(Exception, match="Failed to parse vulnerability report"):
            run_trivy_scan("https://example.com/repo")


def test_run_trivy_scan_image_no_tag():
    mock_json = '{"Vulnerabilities": []}'

    with patch("rover.scanner.DockerContainer") as MockDockerContainer:
        mock_container_instance = MagicMock()
        MockDockerContainer.return_value = mock_container_instance

        mock_client = MagicMock()
        mock_client.client.containers.get.return_value.wait.return_value = {
            "StatusCode": 0
        }
        mock_container_instance.get_docker_client.return_value = mock_client
        mock_container_instance.get_logs.return_value = (mock_json.encode("utf-8"), b"")

        # Run test
        results, commit_hash, tags_str = run_trivy_scan("ubuntu", target_type="image")

        assert results == {"Vulnerabilities": []}
        assert commit_hash == "latest"
        assert tags_str == "ubuntu"
        mock_container_instance.with_command.assert_called_with("image ubuntu -f json")


def test_run_trivy_scan_image_with_git_ref():
    mock_json = '{"Vulnerabilities": []}'

    with patch("rover.scanner.DockerContainer") as MockDockerContainer:
        mock_container_instance = MagicMock()
        MockDockerContainer.return_value = mock_container_instance

        mock_client = MagicMock()
        mock_client.client.containers.get.return_value.wait.return_value = {
            "StatusCode": 0
        }
        mock_container_instance.get_docker_client.return_value = mock_client
        mock_container_instance.get_logs.return_value = (mock_json.encode("utf-8"), b"")

        # Run test with git_ref provided
        results, commit_hash, tags_str = run_trivy_scan(
            "ubuntu", git_ref="20.04", target_type="image"
        )

        assert results == {"Vulnerabilities": []}
        assert commit_hash == "latest"
        assert tags_str == "ubuntu:20.04"
        mock_container_instance.with_command.assert_called_with(
            "image ubuntu:20.04 -f json"
        )


def test_run_trivy_scan_image_with_existing_tag_and_git_ref():
    mock_json = '{"Vulnerabilities": []}'

    with patch("rover.scanner.DockerContainer") as MockDockerContainer:
        mock_container_instance = MagicMock()
        MockDockerContainer.return_value = mock_container_instance

        mock_client = MagicMock()
        mock_client.client.containers.get.return_value.wait.return_value = {
            "StatusCode": 0
        }
        mock_container_instance.get_docker_client.return_value = mock_client
        mock_container_instance.get_logs.return_value = (mock_json.encode("utf-8"), b"")

        # Run test where url already has a tag, but git_ref is also provided
        # Current logic says it should ignore git_ref and keep the original url tag
        results, commit_hash, tags_str = run_trivy_scan(
            "ubuntu:22.04", git_ref="20.04", target_type="image"
        )

        assert results == {"Vulnerabilities": []}
        assert commit_hash == "latest"
        assert tags_str == "ubuntu:22.04"
        mock_container_instance.with_command.assert_called_with(
            "image ubuntu:22.04 -f json"
        )


@patch("rover.scanner.urllib.request.urlopen")
def test_run_major_component_scan_success(mock_urlopen):
    mock_response = MagicMock()
    mock_response.read.return_value = (
        b'{"eol": "2026-11-12", "releaseDate": "2021-09-30"}'
    )
    mock_urlopen.return_value.__enter__.return_value = mock_response

    with patch("rover.scanner.scan_queue.get_cached_eol_data", return_value=None):
        with patch("rover.scanner.scan_queue.set_cached_eol_data") as mock_set:
            data, source, status = run_major_component_scan("postgresql", "14")
            assert data["eol"] == "2026-11-12"
            assert source == "eol_api"
            assert status == "fresh"
            mock_set.assert_called_once()


@patch("rover.scanner.scan_queue.get_cached_eol_data")
def test_run_major_component_scan_cached(mock_get_cached):
    mock_get_cached.return_value = '{"eol": "2026-11-12", "releaseDate": "2021-09-30"}'

    data, source, status = run_major_component_scan("postgresql", "14")
    assert data["eol"] == "2026-11-12"
    assert source == "eol_cache"
    assert status == "cached"


# ── Semgrep scanner tests ─────────────────────────────────────────────────────

@patch("rover.scanner.subprocess.run")
def test_run_semgrep_scan_success(mock_run):
    """Semgrep returns JSON with findings; parsed results are returned."""
    mock_run.side_effect = _mock_subprocess_run
    mock_json = json.dumps({
        "results": [
            {
                "check_id": "python.security.audit.exec-detected",
                "path": "app/views.py",
                "start": {"line": 42},
                "extra": {"severity": "ERROR", "message": "Use of exec() detected"},
            }
        ],
        "errors": [],
    })

    with patch("rover.scanner.DockerContainer") as MockDockerContainer:
        mock_container = MagicMock()
        MockDockerContainer.return_value = mock_container

        mock_client = MagicMock()
        # Semgrep exits 1 when findings are found — not an error
        mock_client.client.containers.get.return_value.wait.return_value = {"StatusCode": 1}
        mock_container.get_docker_client.return_value = mock_client
        mock_container.get_logs.return_value = (mock_json.encode("utf-8"), b"")

        results, commit_hash, tags_str = run_semgrep_scan("https://github.com/example/repo")

        assert "results" in results
        assert results["results"][0]["check_id"] == "python.security.audit.exec-detected"
        assert commit_hash == "mocked_hash"
        assert tags_str == "v1.0"
        mock_container.start.assert_called_once()
        mock_container.stop.assert_called_once()


@patch("rover.scanner.subprocess.run")
def test_run_semgrep_scan_no_results(mock_run):
    """Semgrep exits 0 with an empty results list."""
    mock_run.side_effect = _mock_subprocess_run
    mock_json = json.dumps({"results": [], "errors": []})

    with patch("rover.scanner.DockerContainer") as MockDockerContainer:
        mock_container = MagicMock()
        MockDockerContainer.return_value = mock_container

        mock_client = MagicMock()
        mock_client.client.containers.get.return_value.wait.return_value = {"StatusCode": 0}
        mock_container.get_docker_client.return_value = mock_client
        mock_container.get_logs.return_value = (mock_json.encode("utf-8"), b"")

        results, commit_hash, tags_str = run_semgrep_scan("https://github.com/example/repo")

        assert results == {"results": [], "errors": []}
        assert commit_hash == "mocked_hash"


@patch("rover.scanner.subprocess.run")
def test_run_semgrep_scan_clone_failure(mock_run):
    """Clone failure raises a clear exception before Docker is touched."""
    mock_run.side_effect = CalledProcessError(
        128, "git", stderr=b"fatal: repository not found"
    )

    with patch("rover.scanner.DockerContainer") as MockDockerContainer:
        with pytest.raises(Exception, match="Failed to clone target repository"):
            run_semgrep_scan("https://github.com/example/nonexistent")

        # Docker container should never have been instantiated
        MockDockerContainer.assert_not_called()
