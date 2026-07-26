---
id: "202607261121"
type: Feature
title: Semgrep Pro Authentication
milestone: "M5"
feature_status: planned
dependencies:
  - M1
created: "2026-07-26T11:21:00Z"
updated: "2026-07-26T11:21:00Z"
tags:
  - roadmap/feature
  - roadmap/m5-semgrep-pro
  - status/planned
status: stable
stale_after: "2027-01-01"
aliases:
  - Milestone 5
---

# Milestone 5: Semgrep Pro Authentication

> **Summary**: Enables the Semgrep Pro engine and auth-gated rulesets by authenticating with a saved token.

## 1. Feature Sub-components & Requirements

### 5.1 · Semgrep Token Injection
- Add `semgrep_token` credential type to the Vault.
- Inject `SEMGREP_APP_TOKEN` environment variable into the ephemeral Semgrep scan container.
- Update scan report UI to display an indicator showing whether the scan utilized the free engine or Semgrep Pro.

## 2. Dependencies
- **Prerequisites**: [[m1-credential-management|M1 (Credential Management)]].
- **Enables**: [[m9-release-reports-and-api|M9 (Release Reports & API)]].

## 3. Related Concepts & Indices
- [[semgrep-scanner-plugin|Semgrep SAST Scanner Plugin]]
- [[roadmap-moc|ROVER Roadmap Map of Content]]
