---
id: "202607261118"
type: Feature
title: Snyk Integration
milestone: "M2"
feature_status: planned
dependencies:
  - M1
created: "2026-07-26T11:18:00Z"
updated: "2026-07-26T11:18:00Z"
tags:
  - roadmap/feature
  - roadmap/m2-snyk
  - status/planned
status: stable
stale_after: "2027-01-01"
aliases:
  - Milestone 2
  - Snyk Scanner Feature
---

# Milestone 2: Snyk Integration

> **Summary**: Expands ROVER's scanner suite with Snyk for both SAST and supply-chain (OSS/CVE) analysis.

## 1. Feature Sub-components & Detailed Requirements

### 2.1 · Snyk Authentication (via Credential Vault)
- Add `snyk_token` credential type to the Vault.
- Worker retrieves the stored token and injects it into the Snyk container environment at scan time.
- **Graceful Fallback**: If no token is stored, Snyk operates in unauthenticated mode (limited rate/features).

### 2.2 · Snyk Supply Chain (OSS / CVE)
- Launch ephemeral `snyk/snyk` container (pinned directly to an immutable `sha256` digest per the [[container-image-digest-pinning|Digest Pinning Policy]]).
- Scan Git repository assets for known OSS dependencies and CVE vulnerabilities.
- Persist findings in a `snyk_oss_findings` table.
- Surface results in a dedicated **Snyk OSS** tab on the report UI (parallel to the Trivy tab).

### 2.3 · Snyk Code (SAST)
- Invoke Snyk Code analysis on repository source code assets.
- Persist findings in a `snyk_sast_findings` table.
- Surface results in a dedicated **Snyk Code** tab on the report UI (parallel to the Semgrep tab).
- Cache results by Git commit SHA (matching the strategy used for Semgrep).

## 2. Dependencies
- **Prerequisites**: [[m1-credential-management|M1 (Credential Management)]].
- **Enables**: [[m9-release-reports-and-api|M9 (Release Reports & API)]].

## 3. Related Concepts & Indices
- [[trivy-scanner-plugin|Trivy Scanner Plugin]]
- [[semgrep-scanner-plugin|Semgrep SAST Scanner Plugin]]
- [[roadmap-moc|ROVER Roadmap Map of Content]]
