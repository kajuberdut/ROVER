---
title: Public REST API & OpenAPI
description: Overview of R.O.V.E.R. public machine-to-machine REST API endpoints and OpenAPI 3.0 specification.
---

R.O.V.E.R. exposes a full programmatic REST & Machine-to-Machine API for external automation.

---

## Interactive Swagger UI & OpenAPI Spec

- **Interactive Swagger Explorer**: Accessible at [/api/docs](/api/docs) (or [/api/swagger](/api/swagger)).
- **OpenAPI 3.0 Schema**: Served as raw JSON at [/api/openapi.json](/api/openapi.json).

---

## Authentication

All API requests must be authenticated using an API Token in the `Authorization` header:

```http
Authorization: Bearer rov_tok_abc123...
```

Create API tokens in **User Settings** > **🔑 API Tokens** (`/settings/tokens`). Choose `Read-Only` for monitoring dashboards or `Write` for CI/CD pipelines.

---

## Core Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/ci/image-metadata` | Ingest CI container image SHA256 hashes, repo URIs, commit SHAs, and build URLs. |
| `GET` | `/api/products/{id}/schedules` | List automated scan schedules for a product. |
| `POST` | `/api/products/{id}/schedules` | Create a new scan schedule. |
| `POST` | `/api/schedules/{id}?action=trigger` | Manually dispatch an immediate background scan run. |
| `GET` | `/api/schedules/{id}/logs` | Retrieve schedule execution audit history logs and live scanner progress. |
| `GET` | `/api/eol/all` | Fetch all cached End-Of-Life component lifecycle records. |
| `GET` | `/api/helm/repo/charts` | Discover charts from a remote Helm repository `index.yaml`. |
