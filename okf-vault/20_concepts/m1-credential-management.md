---
id: "202607261117"
type: Feature
title: Credential Management
milestone: "M1"
feature_status: completed
dependencies: []
created: "2026-07-26T11:17:00Z"
updated: "2026-07-26T11:17:00Z"
tags:
  - roadmap/feature
  - roadmap/m1-credentials
  - status/completed
status: stable
stale_after: "2027-01-01"
aliases:
  - Milestone 1
  - Credential Vault Feature
---

# Milestone 1: Credential Management (Completed)

> **Summary**: Provides a secure, admin-managed store for named secrets powered by OpenBao (`openbao/openbao:latest`) and PostgreSQL metadata (`credentials` table). Serves as the foundation for Milestones 2–5, 6, 7, and 13.

## 1. Feature Sub-components & Capabilities Delivered

### 1.1 · Credential Vault (Delivered)
- **Admin UI**: Accessible at `/admin/credentials` for CRUD operations on named credentials (`git_token`, `registry_token`, `snyk_token`, `semgrep_token`, `smtp_password`, `generic`).
- **OpenBao Client**: Integrated REST client (`src/rover/vault.py`) utilizing AppRole machine-to-machine authentication.
- **Secure Vault Storage**: Secret values are stored encrypted directly in OpenBao; password manager ignore attributes (`data-bwignore="true"`) prevent browser extension interference.
- **Scoping Mechanics**: Supports system-wide (global) credentials and product-specific credential overrides via `db.get_unmasked_secret()`.

## 2. Dependencies & Direct Dependents
- **Prerequisites**: None.
- **Enables**: [[m2-snyk-integration|M2 (Snyk Integration)]], [[m3-private-source-repository-support|M3 (Private Git Repos)]], [[m4-private-container-registry-support|M4 (Private Registries)]], [[m5-semgrep-pro-authentication|M5 (Semgrep Pro)]], [[m6-notifications|M6 (Notifications)]], [[m13-outbound-webhooks|M13 (Outbound Webhooks)]].

## 3. Related Concepts & Indices
- [[roadmap-moc|ROVER Roadmap Map of Content]]
