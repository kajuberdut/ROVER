import os
from unittest.mock import MagicMock, patch

import falcon
import platformdirs
import pytest
from falcon import testing

from rover import scan_queue


@pytest.fixture
def client():
    # Setup isolated test database for proxy cache tests
    cache_dir = platformdirs.user_cache_dir("rover_test")
    os.makedirs(cache_dir, exist_ok=True)
    scan_queue.DB_PATH = os.path.join(cache_dir, "rover_test_proxy.db")
    scan_queue.init_db()

    # We must yield the client, then cleanup if necessary, but the key is we MUST clear the cache BEFORE each test
    with scan_queue.get_db_connection() as conn:
        with conn:
            conn.execute("DELETE FROM eol_cache")  # Clear cache before tests

    # Remove auth middleware for isolated proxy testing
    from rover.app import app as real_app

    real_app._middleware = ([], [], [])

    return testing.TestClient(real_app)


@patch("rover.eol_proxy.urllib.request.urlopen")
def test_proxy_all_components_success(mock_urlopen, client):
    # Mocking first external API call
    mock_response = MagicMock()
    mock_response.read.return_value = b'["postgresql", "python", "alpine"]'
    mock_urlopen.return_value.__enter__.return_value = mock_response

    # First request: should hit external API & cache it
    resp1 = client.simulate_get("/api/eol/all")
    assert resp1.status == falcon.HTTP_200
    assert resp1.json == ["postgresql", "python", "alpine"]
    mock_urlopen.assert_called_once()
    mock_urlopen.reset_mock()

    # Second request: should return cached data (urlopen logic NOT triggered)
    resp2 = client.simulate_get("/api/eol/all")
    assert resp2.status == falcon.HTTP_200
    assert resp2.json == ["postgresql", "python", "alpine"]
    mock_urlopen.assert_not_called()


@patch("rover.eol_proxy.urllib.request.urlopen")
def test_proxy_product_cycles_success(mock_urlopen, client):
    mock_response = MagicMock()
    mock_response.read.return_value = b'[{"cycle": "14", "eol": "2026-11-12"}]'
    mock_urlopen.return_value.__enter__.return_value = mock_response

    # First request
    resp1 = client.simulate_get("/api/eol/postgresql")
    assert resp1.status == falcon.HTTP_200
    assert resp1.json == [{"cycle": "14", "eol": "2026-11-12"}]
    mock_urlopen.assert_called_once()
    mock_urlopen.reset_mock()

    # Second request hits cache
    resp2 = client.simulate_get("/api/eol/postgresql")
    assert resp2.status == falcon.HTTP_200
    assert resp2.json == [{"cycle": "14", "eol": "2026-11-12"}]
    mock_urlopen.assert_not_called()


@patch("rover.eol_proxy.urllib.request.urlopen")
def test_proxy_product_not_found(mock_urlopen, client):
    import urllib.error

    mock_urlopen.side_effect = urllib.error.HTTPError(
        url="https://endoflife.date/api/invalid_product.json",
        code=404,
        msg="Not Found",
        hdrs={},
        fp=None,
    )

    resp = client.simulate_get("/api/eol/invalid_product")
    assert resp.status == falcon.HTTP_404
