---
id: "202607261137"
type: Feature
title: SQL Schema Migrations
milestone: "A4"
feature_status: completed
dependencies: []
created: "2026-07-26T11:37:00Z"
updated: "2026-07-26T11:37:00Z"
tags:
  - roadmap/architecture
  - roadmap/a4-migrations
  - status/completed
status: stable
stale_after: "2027-01-01"
aliases:
  - Architecture Target A4
  - Shipship Migrations
---

# Architecture Target A4: SQL Schema Migrations (Completed)

> **Summary**: Implemented automatic versioned SQL schema migrations in `migrations/` via `shipship` (a refactored version of `yoyo-migrations`).

## 1. Capabilities Delivered
- Automated execution of versioned migrations against PostgreSQL backend (`0001_initial.sql`, `0002_admin_notifications.sql`, `0003_credentials_table.sql`).

## 2. Related Concepts & Indices
- [[db-schema-standards|Database Schema & Type Standards]]
- [[roadmap-moc|ROVER Roadmap Map of Content]]
