---
id: "202607261122"
type: Feature
title: Notifications System
milestone: "M6"
feature_status: planned
dependencies:
  - M1
created: "2026-07-26T11:22:00Z"
updated: "2026-07-26T11:22:00Z"
tags:
  - roadmap/feature
  - roadmap/m6-notifications
  - status/planned
status: stable
stale_after: "2027-01-01"
aliases:
  - Milestone 6
---

# Milestone 6: Notifications System

> **Summary**: Delivers per-product email alerts to keep teams informed of new security findings without requiring manual dashboard polling.

## 1. Feature Sub-components & Requirements

### 6.1 · SMTP Credential & Configuration
- Admin UI to configure named SMTP profiles (host, port, sender address, TLS mode).
- Store SMTP passwords securely in the Credential Vault (`smtp_password`).
- Built using standard library `smtplib` (zero external dependencies).

### 6.2 · Notification Rules
- Per-product notification rules:
  - **Every Scan**: Email on completion regardless of findings.
  - **New Vulnerabilities Only**: Email only when a scan introduces a finding not present in the previous scan for that asset.
- Configurable recipient list per product.
- Notification content includes: product name, release, asset, scanner, severity counts, and direct report URL.

### 6.3 · Notification Delivery Execution
- Worker sends email alerts after scan job completion using the active SMTP profile.
- Single attempt delivery policy with logged errors (no retry storm).

## 2. Dependencies
- **Prerequisites**: [[m1-credential-management|M1 (Credential Management)]].
- **Enables**: [[m13-outbound-webhooks|M13 (Outbound Webhooks)]].

## 3. Related Concepts & Indices
- [[roadmap-moc|ROVER Roadmap Map of Content]]
