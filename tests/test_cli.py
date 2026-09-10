import json
import sys
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure cli/src is on python path for tests
cli_src = str(Path(__file__).resolve().parent.parent / "cli" / "src")
if cli_src not in sys.path:
    sys.path.insert(0, cli_src)

import pytest
from rover_cli.main import handle_audit_logs, handle_publish_metadata, main


def test_cli_publish_metadata_success() -> None:
    fake_args = MagicMock()
    fake_args.token = "test-token"
    fake_args.url = "http://localhost:8000"
    fake_args.hash = "sha256:12345"
    fake_args.repo = "https://github.com/org/repo"
    fake_args.commit = "abc1234"
    fake_args.job_url = "https://ci.example.com/job/1"
    fake_args.tags = "latest,v1.0"
    fake_args.metadata = '{"builder": "pytest"}'

    fake_response = MagicMock()
    fake_response.status = 200
    fake_response.read.return_value = b'{"ok": true}'
    fake_response.__enter__.return_value = fake_response

    with (
        patch("urllib.request.urlopen", return_value=fake_response) as mock_urlopen,
        patch("sys.stdout", new_callable=StringIO) as mock_stdout,
    ):
        handle_publish_metadata(fake_args)
        assert "Success (200)" in mock_stdout.getvalue()

        # Check request sent
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == "http://localhost:8000/api/ci/image-metadata"
        assert req.headers["Authorization"] == "Bearer test-token"
        payload = json.loads(req.data.decode("utf-8"))
        assert payload["image_hash"] == "sha256:12345"
        assert payload["image_tags"] == ["latest", "v1.0"]


def test_cli_publish_metadata_missing_token() -> None:
    fake_args = MagicMock()
    fake_args.token = None

    with (
        patch.dict("os.environ", {}, clear=True),
        patch("sys.stderr", new_callable=StringIO) as mock_stderr,
        pytest.raises(SystemExit) as exc_info,
    ):
        handle_publish_metadata(fake_args)

    assert exc_info.value.code == 1
    assert (
        "ROVER_API_TOKEN environment variable or --token flag is required"
        in mock_stderr.getvalue()
    )


def test_cli_audit_logs_success_table() -> None:
    fake_args = MagicMock()
    fake_args.token = "admin-token"
    fake_args.url = "http://localhost:8000"
    fake_args.action = "user.invite_create"
    fake_args.resource_type = "user_invite"
    fake_args.resource_id = None
    fake_args.user_sub = None
    fake_args.limit = 10
    fake_args.offset = 0
    fake_args.json = False

    fake_data = {
        "audit_logs": [
            {
                "id": "log-1",
                "action": "user.invite_create",
                "user_email": "admin@example.com",
                "user_sub": "sub-123",
                "resource_type": "user_invite",
                "resource_id": "inv-456",
                "ip_address": "127.0.0.1",
                "created_at": "2026-09-09T18:00:00.000Z",
            }
        ],
        "count": 1,
    }

    fake_response = MagicMock()
    fake_response.read.return_value = json.dumps(fake_data).encode("utf-8")
    fake_response.__enter__.return_value = fake_response

    with (
        patch("urllib.request.urlopen", return_value=fake_response) as mock_urlopen,
        patch("sys.stdout", new_callable=StringIO) as mock_stdout,
    ):
        handle_audit_logs(fake_args)
        output = mock_stdout.getvalue()
        assert "Audit Logs (1 total matching entries):" in output
        assert "user.invite_create" in output
        assert "admin@example.com" in output

        req = mock_urlopen.call_args[0][0]
        assert "action=user.invite_create" in req.full_url
        assert "resource_type=user_invite" in req.full_url
        assert req.headers["Authorization"] == "Bearer admin-token"


def test_cli_audit_logs_success_json() -> None:
    fake_args = MagicMock()
    fake_args.token = "admin-token"
    fake_args.url = "http://localhost:8000"
    fake_args.action = None
    fake_args.resource_type = None
    fake_args.resource_id = None
    fake_args.user_sub = None
    fake_args.limit = 5
    fake_args.offset = 0
    fake_args.json = True

    fake_data = {
        "audit_logs": [],
        "count": 0,
    }

    fake_response = MagicMock()
    fake_response.read.return_value = json.dumps(fake_data).encode("utf-8")
    fake_response.__enter__.return_value = fake_response

    with (
        patch("urllib.request.urlopen", return_value=fake_response),
        patch("sys.stdout", new_callable=StringIO) as mock_stdout,
    ):
        handle_audit_logs(fake_args)
        output = mock_stdout.getvalue()
        parsed = json.loads(output)
        assert parsed["audit_logs"] == []
        assert parsed["count"] == 0


def test_cli_main_entrypoint() -> None:
    with (
        patch("sys.argv", ["rover-cli", "audit-logs", "--limit", "5"]),
        patch.dict("os.environ", {"ROVER_API_TOKEN": "test-token"}),
        patch("rover_cli.main.handle_audit_logs") as mock_handle,
    ):
        main()
        mock_handle.assert_called_once()
