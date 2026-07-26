---
id: "202607261131"
type: Feature
title: CI/CD Integration API & CLI
milestone: "M15"
feature_status: planned
dependencies:
  - M9
  - M11
created: "2026-07-26T11:31:00Z"
updated: "2026-07-26T11:31:00Z"
tags:
  - roadmap/feature
  - roadmap/m15-cicd-api
  - status/planned
status: stable
stale_after: "2027-01-01"
aliases:
  - Milestone 15
---

# Milestone 15: CI/CD Integration API & CLI

> **Summary**: Enables CI/CD pipelines (GitHub Actions, GitLab CI, Jenkins) to use ROVER as an automated security gate. (High-Value Addition)

## 1. Feature Sub-components & Requirements

### 15.1 · Scan Trigger Endpoint
- `POST /api/v1/releases/{release_id}/scan`: Enqueues full scans for all release assets. Returns `{ "job_id": "...", "status": "queued" }`.

### 15.2 · Job Status Endpoint
- `GET /api/v1/jobs/{job_id}/status`: Returns job state (`queued`, `running`, `complete`, `failed`) and policy pass/fail verdict.

### 15.3 · CLI Helper (`rover-scan`)
- Thin CLI wrapper tool polling job completion and exiting non-zero on policy failure.

## 2. Dependencies
- **Prerequisites**: [[m9-release-reports-and-api|M9]], [[m11-pass-fail-policy-rules|M11]].
- **Enables**: None.

## 3. Related Concepts & Indices
- [[roadmap-moc|ROVER Roadmap Map of Content]]
