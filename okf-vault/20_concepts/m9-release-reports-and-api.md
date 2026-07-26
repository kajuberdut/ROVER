---
id: "202607261125"
type: Feature
title: Release Reports & Export API
milestone: "M9"
feature_status: planned
dependencies:
  - M2
  - M3
  - M4
  - M5
created: "2026-07-26T11:25:00Z"
updated: "2026-07-26T11:25:00Z"
tags:
  - roadmap/feature
  - roadmap/m9-reports-api
  - status/planned
status: stable
stale_after: "2027-01-01"
aliases:
  - Milestone 9
  - Release Reports API
---

# Milestone 9: Release Reports & Export API

> **Summary**: Provides a machine-readable, exportable JSON summary of all ROVER-tracked scan data for a given release.

## 1. Feature Sub-components & Requirements

### 9.1 · Release Report (JSON Document)
Consolidated JSON schema (`"schema_version": "1.0"`):
```json
{
  "release": { "id": "...", "version": "..." },
  "assets": [
    {
      "asset": { "name": "..." },
      "trivy": { ... },
      "semgrep": { ... },
      "snyk_oss": { ... },
      "snyk_sast": { ... }
    }
  ],
  "summary": { "critical": 0, "high": 0, "medium": 0, "low": 0 }
}
```
- Downloadable via dashboard UI button.

### 9.2 · Report API Endpoint
- Endpoint: `GET /api/v1/releases/{release_id}/report`.
- Authenticated via OIDC session cookie or static API token (`rover_api_token` credential type).
- Content-negotiated via `Accept: application/json` vs `Accept: text/html`.

## 2. Dependencies
- **Prerequisites**: [[m2-snyk-integration|M2]], [[m3-private-source-repository-support|M3]], [[m4-private-container-registry-support|M4]], [[m5-semgrep-pro-authentication|M5]].
- **Enables**: [[m15-ci-cd-integration-api|M15 (CI/CD API)]], [[m17-audit-log|M17 (Audit Log)]].

## 3. Related Concepts & Indices
- [[roadmap-moc|ROVER Roadmap Map of Content]]
