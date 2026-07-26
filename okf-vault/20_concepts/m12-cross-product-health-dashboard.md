---
id: "202607261128"
type: Feature
title: Cross-Product Health Dashboard
milestone: "M12"
feature_status: planned
dependencies:
  - M11
  - M14
created: "2026-07-26T11:28:00Z"
updated: "2026-07-26T11:28:00Z"
tags:
  - roadmap/feature
  - roadmap/m12-health-dashboard
  - status/planned
status: stable
stale_after: "2027-01-01"
aliases:
  - Milestone 12
---

# Milestone 12: Cross-Product Health Dashboard

> **Summary**: Top-level status board providing an at-a-glance executive view of security posture across all products. (MVP Gap feature)

## 1. Feature Sub-components & Requirements

### 12.1 · Health Overview Page
- `/dashboard` landing page with product cards displaying policy status badges, severity pills, scan recency, and vulnerability trend arrows.

### 12.2 · Summary Metrics Bar
- Top-level executive summary bar aggregating total open criticals, policy failure counts, and stale un-scanned assets.

## 2. Dependencies
- **Prerequisites**: [[m11-pass-fail-policy-rules|M11]], [[m14-vulnerability-trend-charts|M14]].
- **Enables**: None.

## 3. Related Concepts & Indices
- [[roadmap-moc|ROVER Roadmap Map of Content]]
