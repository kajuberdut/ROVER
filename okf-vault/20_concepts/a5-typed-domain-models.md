---
id: "202607261138"
type: Feature
title: Typed Domain Models
milestone: "A5"
feature_status: planned
dependencies: []
created: "2026-07-26T11:38:00Z"
updated: "2026-07-26T11:38:00Z"
tags:
  - roadmap/architecture
  - roadmap/a5-domain-models
  - status/planned
status: stable
stale_after: "2027-01-01"
aliases:
  - Architecture Target A5
---

# Architecture Target A5: Typed Domain Models

> **Summary**: Replaces raw `dict[str, Any]` database query returns with strongly-typed stdlib `@dataclass` models (e.g. `ScanJob`, `Asset`, `Product`).

## 1. Technical Requirements & Benefits
- Eliminates string-key typos and runtime KeyError crashes.
- Enables complete IDE autocomplete and `mypy` static type checking across routes, DB modules, and scanner plugins.
- Zero extra dependencies (uses stdlib `dataclasses`).

## 2. Related Concepts & Indices
- [[rover-scanner-plugin-specification|ROVER Scanner Plugin Specification]]
- [[roadmap-moc|ROVER Roadmap Map of Content]]
