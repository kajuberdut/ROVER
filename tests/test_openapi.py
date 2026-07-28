"""tests/test_openapi.py: Unit tests for OpenAPI schema endpoint and Swagger UI documentation page."""

from falcon import testing

from rover import openapi
from rover.routes import create_app


def test_openapi_schema_generation():
    schema = openapi.get_openapi_schema()
    assert schema["openapi"] == "3.0.3"
    assert "info" in schema
    assert "paths" in schema
    assert "/api/ci/image-metadata" in schema["paths"]
    assert "/api/products/{product_id}/schedules" in schema["paths"]
    assert "/api/schedules/{schedule_id}" in schema["paths"]


def test_openapi_routes():
    app = create_app()
    app._middleware = ([], [], [])
    client = testing.TestClient(app)

    # Test OpenAPI JSON endpoint
    resp_json = client.simulate_get("/api/openapi.json")
    assert resp_json.status_code == 200
    data = resp_json.json
    assert data["openapi"] == "3.0.3"

    # Test Swagger UI documentation page
    resp_docs = client.simulate_get("/docs")
    assert resp_docs.status_code == 200
    assert "swagger-ui" in resp_docs.text

    # Test API docs alias endpoint
    resp_api_docs = client.simulate_get("/api/docs")
    assert resp_api_docs.status_code == 200
    assert "swagger-ui" in resp_api_docs.text


def test_api_token_header_authentication():
    # Test Bearer header authentication handling
    app = create_app()
    client = testing.TestClient(app)

    # Invalid token via Authorization Bearer header should return 401 Unauthorized
    resp = client.simulate_get(
        "/api/ci/image-metadata",
        headers={"Authorization": "Bearer invalid_token_123"},
    )
    assert resp.status_code == 401
