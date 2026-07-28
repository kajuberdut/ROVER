---
id: "202607261122"
type: Feature
title: Notifications System & Webhooks Architecture
milestone: "M6"
feature_status: planned
dependencies:
  - M1
created: "2026-07-26T11:22:00Z"
updated: "2026-07-28T09:25:00Z"
tags:
  - roadmap/feature
  - roadmap/m6-notifications
  - status/planned
status: stable
stale_after: "2027-01-01"
aliases:
  - Milestone 6
  - Milestone 13
  - Event Driven Notifications
---

# Milestone 6 & 13: Event-Driven Notification & Webhook Framework

> **Summary**: Unified event-driven notification framework for R.O.V.E.R. supporting per-user and per-product notification channels (Webhooks, Slack, MS Teams, SMTP, AWS SES), OpenBao Vault credential integration, and configurable EOL lead times (e.g. 90, 120, 180 days).

---

## 1. Architectural Blueprint & Concept Reference

For detailed system mechanics, transport adapters, and message flows, see:
👉 **[[notification_system_architecture|Notification System Architecture]]**

---

## 2. Implementation Units & Actionable Roadmap

The notification system implementation is structured into 6 standalone units of work:

### 🧩 Unit 1: Notification Destinations Schema & OpenBao Vault Integration
- **Tasks**:
  1. Add `notification_destinations` table in `schema.py` (`user_id`, `product_id`, `destination_type`, `name`, `config_json`).
  2. Implement OpenBao Vault secret storage for sensitive credentials (`smtp_password`, `aws_secret_key`, `webhook_secret`).
  3. Write DB helper functions (`add_destination`, `get_destinations`, `delete_destination`).
- **Success Criteria**:
  - `python3 okf-vault/scripts/validate_schema.py` passes cleanly.
  - Unit tests in `tests/test_notifications.py` verify DB CRUD and OpenBao secret encryption/retrieval.

### 🧩 Unit 2: Per-User & Product Rule Engine with EOL Warning Lead Times
- **Tasks**:
  1. Add `notification_rules` table in `schema.py` (`scope`, `user_id`, `product_id`, `event_type`, `min_severity`, `eol_warning_days`).
  2. Create rule matching engine `evaluate_notification_rules(event_type, product_id, severity, eol_days_remaining)`.
- **Success Criteria**:
  - Rule evaluation correctly triggers when `days_remaining <= eol_warning_days` (e.g., EOL in 90 days).
  - Severity filters (`CRITICAL`, `HIGH`) suppress low-severity noise.

### 🧩 Unit 3: Pluggable Transports (Webhook, Slack/Teams, SMTP, AWS SES)
- **Tasks**:
  1. Create `src/rover/notifications/transports/` framework.
  2. Build `WebhookTransport` (HTTP POST + HMAC-SHA256 headers).
  3. Build `SlackTransport` (Block Kit payloads).
  4. Build `SmtpTransport` (`smtplib` TLS/STARTTLS).
  5. Build `AwsSesTransport` (AWS SES API delivery).
- **Success Criteria**:
  - Transports execute via mock HTTP/SMTP fixtures in unit tests.
  - HMAC signatures match standard HMAC-SHA256 calculations.

### 🧩 Unit 4: Async Dispatch Engine & Audit Log (`notification_logs`)
- **Tasks**:
  1. Add `notification_logs` table in `schema.py`.
  2. Implement async worker task queue offloading delivery routines.
- **Success Criteria**:
  - Delivery attempts recorded in `notification_logs` (status, HTTP code, duration, error).

### 🧩 Unit 5: User Settings & Product Notification Management UI
- **Tasks**:
  1. Build `/user/settings/notifications` template and route for personal destinations/subscriptions.
  2. Build `/products/{product_id}/settings/notifications` template and route for team destinations/subscriptions.
  3. Implement **Test Ping** button (`POST /api/notifications/destinations/{id}/test`).
- **Success Criteria**:
  - Users can manage personal destinations and set custom EOL lead times.
  - Product admins can set up team Webhooks and Slack alerts.
  - Test ping button delivers immediate visual feedback.

### 🧩 Unit 6: Astro Starlight Documentation Guide
- **Tasks**:
  1. Add `docs/starlight/src/content/docs/guides/notifications.md`.
- **Success Criteria**:
  - `poe docs-build` succeeds cleanly.

---

## 3. Related Concepts & Indices
- [[roadmap-moc|ROVER Roadmap Map of Content]]
- [[notification_system_architecture|Notification System Architecture]]
- [[m1-credential-management|M1: Credential Vault]]
