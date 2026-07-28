---
type: Concept
id: "202607272210"
title: "Public REST & Machine-to-Machine API"
description: "Architecture, OpenAPI 3.0 specification generator, Swagger UI interactive explorer, and API Token authentication for R.O.V.E.R."
created: "2026-07-27T22:10:00Z"
updated: "2026-07-27T22:10:00Z"
tags: [architecture/api, security/authentication, openapi/v3]
status: stable
generated:
  by: "agent:antigravity"
  at: "2026-07-27T22:10:00Z"
verified:
  - by: "human:giblesnot"
    at: "2026-07-27T22:10:00Z"
---

# Public REST & Machine-to-Machine API

The **R.O.V.E.R. Public API** provides programmatic HTTP endpoints for CI/CD pipelines, security automation scripts, and external tools to interact with R.O.V.E.R. without manual web dashboard navigation.

---

## 1. OpenAPI 3.0 Auto-Documentation & Explorer

- **OpenAPI 3.0 Specification**: Available at `/api/openapi.json`. Automatically generates a structured OpenAPI 3.0 schema dictionary detailing all public endpoints, query parameters, request bodies, and response schemas.
- **Interactive Swagger UI**: Served at `/docs` (and `/api/docs`). Renders an interactive Swagger UI browser interface allowing developers to inspect endpoints, test live requests, view schemas, and authenticate with API tokens.
- **Header Navigation**: Accessible directly from the web interface user menu via **📖 API Docs**.

---

## 2. Authentication Security Schemes

The public API supports two standard authentication schemes:

1. **`Authorization: Bearer <token>` Header** (`BearerAuth`):
   Standard RFC 6750 HTTP Authorization header for API tokens created in User Settings > API Tokens.
   ```http
   POST /api/ci/image-metadata HTTP/1.1
   Host: rover.local
   Authorization: Bearer rov_tok_abc123...
   Content-Type: application/json
   ```
2. **Session Cookie Authentication** (`CookieAuth`):
   Automatic session cookie authentication (`rover_session`) for logged-in web browser users.

---

## 3. Public Endpoint Surface

### Machine-to-Machine CI Pipeline Endpoints
- **`POST /api/ci/image-metadata`**: Pipeline ingestion for recording container image SHA256 hashes, source repository URIs, git commit SHAs, image tags, and CI pipeline URLs.

### Scheduled Scan Management Endpoints
- **`GET /api/products/{product_id}/schedules`**: Retrieves all automated scan schedules configured for a product.
- **`POST /api/products/{product_id}/schedules`**: Creates a new background scan schedule (`cron_expression`, `release_id`, `enabled`).
- **`POST /api/schedules/{schedule_id}?action=trigger`**: Manually dispatches an immediate scan run across target assets.
- **`POST /api/schedules/{schedule_id}?action=toggle`**: Toggles schedule status between active and paused.
- **`GET /api/schedules/{schedule_id}/logs`**: Fetches audit execution history logs and real-time scanner job progress.
- **`DELETE /api/schedules/{schedule_id}`**: Deletes a scan schedule.

### System & Proxy Endpoints
- **`GET /api/eol/all`**: Returns cached End-Of-Life component lifecycle records.
- **`GET /api/eol/{product}`**: Returns EOL release cycle records for a specific component (e.g. `python`, `postgres`, `ubuntu`).
- **`GET /api/helm/repo/charts`**: Discovers charts in a remote Helm repository.

---

## 4. Architectural Implementation

- **Specification Builder**: Implemented in [`src/rover/openapi.py`](file:///home/giblesnot/code/ROVER/src/rover/openapi.py).
- **Route Handlers**: Implemented in [`src/rover/routes/api.py`](file:///home/giblesnot/code/ROVER/src/rover/routes/api.py) (`OpenApiJsonResource` and `OpenApiDocsResource`).
- **Route Registration**: Configured in [`src/rover/routes/__init__.py`](file:///home/giblesnot/code/ROVER/src/rover/routes/__init__.py).
