"""tests/test_cli.py — Unit and integration tests for ROVER CLI commands."""

import json
import sys
import urllib.error
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


def test_cli_audit_logs_all_filter_options() -> None:
    fake_args = MagicMock()
    fake_args.token = "admin-token"
    fake_args.url = "https://rover.local"
    fake_args.action = "scans.trigger"
    fake_args.resource_type = "release_asset"
    fake_args.resource_id = "asset-99"
    fake_args.user_sub = "sub-88"
    fake_args.limit = 50
    fake_args.offset = 10
    fake_args.json = False

    fake_data = {"audit_logs": [], "count": 0}
    fake_response = MagicMock()
    fake_response.read.return_value = json.dumps(fake_data).encode("utf-8")
    fake_response.__enter__.return_value = fake_response

    with (
        patch("urllib.request.urlopen", return_value=fake_response) as mock_urlopen,
        patch("sys.stdout", new_callable=StringIO) as mock_stdout,
    ):
        handle_audit_logs(fake_args)
        output = mock_stdout.getvalue()
        assert "No audit log records found." in output

        req = mock_urlopen.call_args[0][0]
        url = req.full_url
        assert "https://rover.local/api/admin/audit_logs?" in url
        assert "action=scans.trigger" in url
        assert "resource_type=release_asset" in url
        assert "resource_id=asset-99" in url
        assert "user_sub=sub-88" in url
        assert "limit=50" in url
        assert "offset=10" in url


def test_cli_audit_logs_missing_token() -> None:
    fake_args = MagicMock()
    fake_args.token = None

    with (
        patch.dict("os.environ", {}, clear=True),
        patch("sys.stderr", new_callable=StringIO) as mock_stderr,
        pytest.raises(SystemExit) as exc_info,
    ):
        handle_audit_logs(fake_args)

    assert exc_info.value.code == 1
    assert (
        "ROVER_API_TOKEN environment variable or --token flag is required"
        in mock_stderr.getvalue()
    )


def test_cli_audit_logs_http_error_handling() -> None:
    fake_args = MagicMock()
    fake_args.token = "invalid-token"
    fake_args.url = "http://localhost:8000"
    fake_args.action = None
    fake_args.resource_type = None
    fake_args.resource_id = None
    fake_args.user_sub = None
    fake_args.limit = 10
    fake_args.offset = 0
    fake_args.json = False

    http_err = urllib.error.HTTPError(
        url="http://localhost:8000/api/admin/audit_logs",
        code=403,
        msg="Forbidden",
        hdrs={},
        fp=StringIO('{"error": "Forbidden: Requires system_admin role"}'),
    )

    with (
        patch("urllib.request.urlopen", side_effect=http_err),
        patch("sys.stderr", new_callable=StringIO) as mock_stderr,
        pytest.raises(SystemExit) as exc_info,
    ):
        handle_audit_logs(fake_args)

    assert exc_info.value.code == 1
    err_output = mock_stderr.getvalue()
    assert "HTTP Error 403: Forbidden" in err_output
    assert "Requires system_admin role" in err_output


def test_cli_audit_logs_connection_error_handling() -> None:
    fake_args = MagicMock()
    fake_args.token = "admin-token"
    fake_args.url = "http://unreachable-host:8000"
    fake_args.action = None
    fake_args.resource_type = None
    fake_args.resource_id = None
    fake_args.user_sub = None
    fake_args.limit = 10
    fake_args.offset = 0
    fake_args.json = False

    url_err = urllib.error.URLError(reason="Name or service not known")

    with (
        patch("urllib.request.urlopen", side_effect=url_err),
        patch("sys.stderr", new_callable=StringIO) as mock_stderr,
        pytest.raises(SystemExit) as exc_info,
    ):
        handle_audit_logs(fake_args)

    assert exc_info.value.code == 1
    assert "Connection Error: Name or service not known" in mock_stderr.getvalue()


def test_cli_main_entrypoint_aliases() -> None:
    for cmd in ["audit-logs", "audit_logs", "audit"]:
        with (
            patch("sys.argv", ["rover-cli", cmd, "--limit", "5"]),
            patch.dict("os.environ", {"ROVER_API_TOKEN": "test-token"}),
            patch("rover_cli.main.handle_audit_logs") as mock_handle,
        ):
            main()
            mock_handle.assert_called_once()


def test_cli_insecure_ssl_context() -> None:
    import ssl

    from rover_cli.main import _get_ssl_context

    # Default secure args
    args_secure = MagicMock()
    args_secure.insecure = False
    with patch.dict("os.environ", {}, clear=True):
        assert _get_ssl_context(args_secure) is None

    # Insecure via flag
    args_insecure = MagicMock()
    args_insecure.insecure = True
    ctx = _get_ssl_context(args_insecure)
    assert ctx is not None
    assert ctx.check_hostname is False
    assert ctx.verify_mode == ssl.CERT_NONE

    # Insecure via ROVER_INSECURE env var
    with patch.dict("os.environ", {"ROVER_INSECURE": "1"}):
        ctx_env = _get_ssl_context(args_secure)
        assert ctx_env is not None
        assert ctx_env.check_hostname is False
        assert ctx_env.verify_mode == ssl.CERT_NONE

    # Insecure via ROVER_SKIP_TLS_VERIFY env var
    with patch.dict("os.environ", {"ROVER_SKIP_TLS_VERIFY": "true"}):
        ctx_skip = _get_ssl_context(args_secure)
        assert ctx_skip is not None
        assert ctx_skip.check_hostname is False
        assert ctx_skip.verify_mode == ssl.CERT_NONE


@pytest.fixture
def sqlite_test_db() -> None:
    from sqlalchemy import create_engine

    from rover.db import connection, schema

    test_engine = create_engine("sqlite:///:memory:")
    connection.engine = test_engine
    schema.metadata.create_all(test_engine)


def test_cli_integration_with_falcon_app(sqlite_test_db: None) -> None:
    from falcon import testing

    from rover.auth import COOKIE_NAME, cookie_serializer
    from rover.db.audit import log_audit_event
    from rover.routes import create_app

    log_audit_event(
        action="scans.trigger",
        resource_type="release_asset",
        resource_id="asset-777",
        user_sub="admin-sub",
        user_email="admin@rover.local",
    )

    app = create_app()
    client = testing.TestClient(app)

    session_data = {
        "sub": "admin-sub",
        "email": "admin@rover.local",
        "name": "Test Admin",
        "role": "system_admin",
        "product_ids": [],
    }
    cookie_val = cookie_serializer.dumps(session_data)
    headers = {"Cookie": f"{COOKIE_NAME}={cookie_val}"}

    res = client.simulate_get(
        "/api/admin/audit_logs?action=scans.trigger", headers=headers
    )
    assert res.status_code == 200
    data = res.json
    assert data["count"] == 1
    assert data["audit_logs"][0]["resource_id"] == "asset-777"
