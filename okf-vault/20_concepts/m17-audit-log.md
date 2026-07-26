---
id: "202607261133"
type: Feature
title: Security Audit Log
milestone: "M17"
feature_status: planned
dependencies:
  - M9
created: "2026-07-26T11:33:00Z"
updated: "2026-07-26T11:33:00Z"
tags:
  - roadmap/feature
  - roadmap/m17-audit-log
  - status/planned
status: stable
stale_after: "2027-01-01"
aliases:
  - Milestone 17
---

# Milestone 17: Security Audit Log

> **Summary**: Provides an append-only, tamper-evident audit log of all security-relevant user and system actions for compliance reporting.

## 1. Feature Sub-components & Requirements

### 17.1 · Audit Event Recording
- Append-only `audit_log` table tracking timestamps, actor IDs, actions, entity targets, and detail JSON payloads.
- Events logged: scan execution, triage actions, policy edits, credential changes, role modifications.

### 17.2 · Audit Log UI & Export
- Admin `/admin/audit` review page and inclusion in JSON release reports (`"audit_trail"` field).

## 2. Dependencies
- **Prerequisites**: [[m9-release-reports-and-api|M9]].
- **Enables**: None.

## 3. Related Concepts & Indices
- [[roadmap-moc|ROVER Roadmap Map of Content]]
