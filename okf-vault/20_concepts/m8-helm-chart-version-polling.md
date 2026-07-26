---
id: "202607261124"
type: Feature
title: Helm Chart Version Polling & Auto Promotion
milestone: "M8"
feature_status: planned
dependencies:
  - M7
  - M3
  - M4
created: "2026-07-26T11:24:00Z"
updated: "2026-07-26T11:24:00Z"
tags:
  - roadmap/feature
  - roadmap/m8-helm-polling
  - status/planned
status: stable
stale_after: "2027-01-01"
aliases:
  - Milestone 8
---

# Milestone 8: Helm Chart Version Polling & Auto Promotion

> **Summary**: Detects when new versions of tracked Helm charts are published and automatically promotes releases.

## 1. Feature Sub-components & Requirements

### 8.1 · Helm Version Watcher
- Periodically polls chart repositories (OCI or HTTP) for newer versions across releases containing Helm chart assets.
- Compares pinned versions against available versions using semver.
- Stores discovered chart versions in `helm_chart_versions` tracking table.

### 8.2 · Automated Release Promotion
- Per-release promotion rules (e.g. `RC* -> RC*+1`, `Dev* -> RC1`).
- Creates a new Release record upon qualifying chart discovery, inheriting asset associations, bumping version labels, and triggering full scans.
- **Approval Gate**: Optional admin confirmation step before new release activation.

## 2. Dependencies
- **Prerequisites**: [[m7-scheduled-scans|M7 (Scheduled Scans)]], [[m3-private-source-repository-support|M3 (Private Git)]], [[m4-private-container-registry-support|M4 (Private Registries)]].
- **Enables**: None.

## 3. Related Concepts & Indices
- [[roadmap-moc|ROVER Roadmap Map of Content]]
