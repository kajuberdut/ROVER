"""tests/test_single_asset_rerun.py: Unit tests for single asset re-run endpoint and db functions."""

from unittest.mock import AsyncMock, MagicMock, patch

from falcon import testing

from rover.routes import create_app


def test_get_release_asset_details_nonexistent():
    mock_conn = MagicMock()
    mock_conn.execute.return_value.fetchone.return_value = None

    with patch("rover.db.products.get_db_connection") as mock_get_db:
        mock_get_db.return_value.__enter__.return_value = mock_conn

        from rover import db

        asset = db.get_release_asset_details("nonexistent-id-0000")
        assert asset is None


def test_single_asset_scan_resource():
    app = create_app()
    client = testing.TestClient(app)

    headers = {"Accept": "application/json", "Authorization": "Bearer test_token"}
    mock_token_data = {"user_sub": "user_123", "permission": "write", "id": "tok_1"}
    mock_user = {
        "sub": "user_123",
        "email": "test@example.com",
        "name": "Admin",
        "role": "system_admin",
    }

    with (
        patch("rover.db.verify_api_token", return_value=mock_token_data),
        patch("rover.db.get_user", return_value=mock_user),
        patch("rover.db.get_user_product_ids", return_value=[]),
        patch("rover.permissions.require_product_read_write", new_callable=AsyncMock),
        patch("rover.db.get_release_asset_details", return_value=None),
    ):
        resp_404 = client.simulate_post(
            "/api/assets/nonexistent-id-0000/scans",
            headers=headers,
        )
        assert resp_404.status_code == 404

    mock_asset = {
        "release_asset_id": "asset-123",
        "release_id": "rel-456",
        "asset_type": "repo",
        "asset_id": "repo-789",
        "git_ref": "main",
        "asset_name": "https://github.com/example/repo.git",
        "source_repo_url": None,
        "image_source_git_ref": None,
    }

    with (
        patch("rover.db.verify_api_token", return_value=mock_token_data),
        patch("rover.db.get_user", return_value=mock_user),
        patch("rover.db.get_user_product_ids", return_value=[]),
        patch("rover.permissions.require_product_read_write", new_callable=AsyncMock),
        patch("rover.db.get_release_asset_details", return_value=mock_asset),
        patch("rover.db.create_job", return_value="job-1") as mock_trivy,
        patch("rover.db.create_semgrep_job", return_value="job-2") as mock_semgrep,
        patch("rover.db.create_snyk_job", return_value="job-3") as mock_snyk,
    ):
        # Test triggering specific scanner: trivy
        resp_trivy = client.simulate_post(
            "/api/assets/asset-123/scans?scanner=trivy",
            headers=headers,
        )
        assert resp_trivy.status_code == 201
        assert resp_trivy.json["dispatched_jobs"] == ["job-1"]
        mock_trivy.assert_called_once_with(
            target_url="https://github.com/example/repo.git",
            target_type="repo",
            git_ref="main",
        )

        # Test triggering all scanners for repo asset
        mock_trivy.reset_mock()
        mock_semgrep.reset_mock()
        mock_snyk.reset_mock()

        resp_all = client.simulate_post(
            "/api/assets/asset-123/scans?scanner=all",
            headers=headers,
        )
        assert resp_all.status_code == 201
        assert len(resp_all.json["dispatched_jobs"]) == 3
        mock_trivy.assert_called_once()
        mock_semgrep.assert_called_once()
        mock_snyk.assert_called_once()
