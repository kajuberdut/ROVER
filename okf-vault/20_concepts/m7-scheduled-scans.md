---
id: "202607261123"
type: Feature
title: Scheduled Scans Engine
milestone: "M7"
feature_status: planned
dependencies: []
created: "2026-07-26T11:23:00Z"
updated: "2026-07-26T11:23:00Z"
tags:
  - roadmap/feature
  - roadmap/m7-scheduled-scans
  - status/planned
status: stable
stale_after: "2027-01-01"
aliases:
  - Milestone 7
---

# Milestone 7: Scheduled Scans Engine

> **Summary**: Automates recurring vulnerability scans on a configurable cadence (hourly, daily, weekly) rather than requiring manual triggers.

## 1. Feature Sub-components & Requirements

### 7.1 · Scan Schedule Configuration
- Per-release schedule settings (cron-style or interval: hourly, daily, weekly).
- Schedules stored in PostgreSQL alongside release metadata.
- Admin and Product Owner UI for schedule management.

### 7.2 · Schedule Executor
- Worker loop checks for releases due for scheduled scans on each iteration (low-overhead DB polling in `rover.db.jobs`).
- Enqueues scan jobs for all release assets when a schedule fires.
- **Cache Awareness**: Respects Semgrep commit SHA caching (Semgrep jobs are only enqueued if commits have changed).

## 2. Dependencies
- **Prerequisites**: None (Notifications optional but recommended).
- **Enables**: [[m8-helm-chart-version-polling|M8 (Helm Polling)]].

## 3. Related Concepts & Indices
- [[roadmap-moc|ROVER Roadmap Map of Content]]
