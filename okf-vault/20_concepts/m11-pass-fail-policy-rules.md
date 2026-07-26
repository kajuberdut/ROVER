---
id: "202607261127"
type: Feature
title: Pass/Fail Policy Rules Engine
milestone: "M11"
feature_status: planned
dependencies:
  - M10
created: "2026-07-26T11:27:00Z"
updated: "2026-07-26T11:27:00Z"
tags:
  - roadmap/feature
  - roadmap/m11-policy-engine
  - status/planned
status: stable
stale_after: "2027-01-01"
aliases:
  - Milestone 11
---

# Milestone 11: Pass/Fail Policy Rules Engine

> **Summary**: Defines per-product or per-release security gates enforcing threshold-based compliance rules. (MVP Gap feature)

## 1. Feature Sub-components & Requirements

### 11.1 · Policy Definition
- Threshold rules by severity/scanner (e.g. `CRITICAL == 0`, `HIGH <= 5`, `SAST HIGH == 0`).
- Excludes triaged findings (`accepted_risk`, `false_positive`).
- ANDed rule evaluation logic.

### 11.2 · Policy Evaluation & Status Display
- Evaluates automatically post-scan (`pass`, `fail`, `no_policy`).
- Prominent badge display on dashboards and JSON reports.

## 2. Dependencies
- **Prerequisites**: [[m10-vulnerability-triage-and-finding-status|M10 (Triage)]].
- **Enables**: [[m12-cross-product-health-dashboard|M12]], [[m15-ci-cd-integration-api|M15]], [[m16-license-compliance|M16]].

## 3. Related Concepts & Indices
- [[roadmap-moc|ROVER Roadmap Map of Content]]
