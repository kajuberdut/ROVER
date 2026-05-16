import os
from unittest.mock import MagicMock, patch

import falcon
import platformdirs
import pytest
from falcon import testing

from rover import scan_queue


from testcontainers.postgres import PostgresContainer
from sqlalchemy import create_engine

@pytest.fixture(scope="session")
def postgres_db():
    with PostgresContainer("postgres:17-alpine") as postgres:
        yield postgres

@pytest.fixture
def client(postgres_db):
    from rover.db import connection, schema
    
    # Override the application engine to use our test container
    connection.engine = create_engine(postgres_db.get_connection_url(driver="psycopg"))
    
    # Initialize the schema
    schema.metadata.create_all(connection.engine)

    # We must yield the client, then cleanup if necessary, but the key is we MUST clear the cache BEFORE each test
    with scan_queue.get_db_connection() as conn:
        from sqlalchemy import text
        conn.execute(text("DELETE FROM eol_cache"))  # Clear cache before tests

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
