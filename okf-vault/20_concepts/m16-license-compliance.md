---
id: "202607261132"
type: Feature
title: Open Source License Compliance
milestone: "M16"
feature_status: planned
dependencies:
  - M11
created: "2026-07-26T11:32:00Z"
updated: "2026-07-26T11:32:00Z"
tags:
  - roadmap/feature
  - roadmap/m16-license-compliance
  - status/planned
status: stable
stale_after: "2027-01-01"
aliases:
  - Milestone 16
---

# Milestone 16: Open Source License Compliance

> **Summary**: Extracts SPDX license metadata from Trivy scans and audits licenses against allow/deny policies. (High-Value Addition)

## 1. Feature Sub-components & Requirements

### 16.1 · License Data Extraction
- Parses SPDX package license identifiers from Trivy JSON outputs into a `license_findings` database table.

### 16.2 · License Policy Configuration
- Admin UI defining license allowlists/denylists (e.g. deny `GPL-3.0`, `AGPL-3.0`; warn on `LGPL-2.1`).

### 16.3 · License Report View & Policy Integration
- Dedicated **Licenses** tab on report UI; integrates license violations into M11 Pass/Fail policy evaluation.

## 2. Dependencies
- **Prerequisites**: [[m11-pass-fail-policy-rules|M11]].
- **Enables**: None.

## 3. Related Concepts & Indices
- [[trivy-scanner-plugin|Trivy Scanner Plugin]]
- [[roadmap-moc|ROVER Roadmap Map of Content]]
