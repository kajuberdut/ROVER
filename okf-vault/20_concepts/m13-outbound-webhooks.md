---
id: "202607261129"
type: Feature
title: Outbound Webhooks Integration
milestone: "M13"
feature_status: completed
dependencies:
  - M1
  - M6
created: "2026-07-26T11:29:00Z"
updated: "2026-07-26T11:29:00Z"
tags:
  - roadmap/feature
  - roadmap/m13-webhooks
  - status/completed
status: stable
stale_after: "2027-01-01"
aliases:
  - Milestone 13
---

# Milestone 13: Outbound Webhooks Integration (Completed)

> **Summary**: Delivers real-time scan alerts to Slack, Microsoft Teams, PagerDuty, or HTTP endpoints. (MVP Gap feature)

## 1. Feature Sub-components & Requirements

### 13.1 · Webhook Profile Configuration
- Admin UI for named webhook profiles (URL, HTTP method, HMAC secret, payload templates).
- Webhook URLs stored in Credential Vault (`webhook_url`).

### 13.2 · Webhook Delivery Execution
- Worker POSTs scan notifications using standard library `urllib.request`.
- Out-of-the-box templates for Slack Block Kit and Teams Adaptive Cards.

## 2. Dependencies
- **Prerequisites**: [[m1-credential-management|M1]], [[m6-notifications|M6]].
- **Enables**: None.

## 3. Related Concepts & Indices
- [[roadmap-moc|ROVER Roadmap Map of Content]]
