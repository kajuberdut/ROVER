---
id: "202607261120"
type: Feature
title: Private Container Registry Support
milestone: "M4"
feature_status: planned
dependencies:
  - M1
created: "2026-07-26T11:20:00Z"
updated: "2026-07-26T11:20:00Z"
tags:
  - roadmap/feature
  - roadmap/m4-private-registry
  - status/planned
status: stable
stale_after: "2027-01-01"
aliases:
  - Milestone 4
---

# Milestone 4: Private Container Registry Support

> **Summary**: Allows ROVER to pull and scan container images from private registries requiring authentication.

## 1. Feature Sub-components & Requirements

### 4.1 · Registry Credential Injection
- Add `registry_token` credential type to the Vault, keyed by registry hostname.
- Inject registry authentication into Trivy or Skopeo via Docker config JSON (`~/.docker/config.json`) or tool `--registry-auth` flags.
- Support standard `username:password` and bearer token format authentication.

## 2. Dependencies
- **Prerequisites**: [[m1-credential-management|M1 (Credential Management)]].
- **Enables**: [[m8-helm-chart-version-polling|M8 (Helm Polling)]], [[m9-release-reports-and-api|M9 (Release Reports & API)]].

## 3. Related Concepts & Indices
- [[trivy-scanner-plugin|Trivy Scanner Plugin]]
- [[roadmap-moc|ROVER Roadmap Map of Content]]
