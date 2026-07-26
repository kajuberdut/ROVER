---
id: "202607261139"
type: Feature
title: Structured JSON Logging
milestone: "A6"
feature_status: planned
dependencies: []
created: "2026-07-26T11:39:00Z"
updated: "2026-07-26T11:39:00Z"
tags:
  - roadmap/architecture
  - roadmap/a6-logging
  - status/planned
status: stable
stale_after: "2027-01-01"
aliases:
  - Architecture Target A6
---

# Architecture Target A6: Structured JSON Logging

> **Summary**: Standardizes application logging using a stdlib JSON formatter to emit machine-parseable log records containing request IDs and job context.

## 1. Technical Requirements & Benefits
- Implements a lightweight `JsonFormatter` emitting `timestamp`, `level`, `logger`, `message`, `job_id`, and `user_sub`.
- Compatible with log aggregators (Loki, Datadog, CloudWatch) and command-line `jq` pipelines.
- Standardizes HTTP access logs with `method`, `path`, `status`, and `duration_ms`.

## 2. Related Concepts & Indices
- [[roadmap-moc|ROVER Roadmap Map of Content]]
