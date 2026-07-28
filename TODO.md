# R.O.V.E.R. Project TODOs & Feature Roadmap

## 1. Event-Driven Notification System (Per-User, Multi-Channel & EOL Advance Warnings)

- [ ] **Unit 1: Notification Destinations Schema & OpenBao Vault Integration**
  - Add `notification_destinations` DB schema supporting `user_id`, `product_id`, and `is_system` scope.
  - Types: `webhook`, `slack`, `smtp`, `aws_ses`.
  - Vault secret path helpers for storing `smtp_password`, `aws_secret_key`, `webhook_secret`.

- [ ] **Unit 2: Per-User & Product Rule Engine with EOL Lead Times**
  - Add `notification_rules` DB schema supporting event types (`scan.completed`, `scan.failed`, `vulnerability.found`, `eol.warning`), severity thresholds, and **`eol_warning_days`** (INTEGER lead time, e.g. 90, 120, 180 days).
  - Create rule evaluation logic firing alerts when `days_remaining <= eol_warning_days`.

- [ ] **Unit 3: Pluggable Transports (Webhook, Slack/Teams, SMTP, AWS SES)**
  - Implement `WebhookTransport` (HTTP POST + HMAC-SHA256 headers).
  - Implement `SlackTransport` (Block Kit payloads).
  - Implement `SmtpTransport` (`smtplib` TLS/STARTTLS).
  - Implement `AwsSesTransport` (AWS SES API delivery).

- [ ] **Unit 4: Async Dispatch Engine & Audit Log (`notification_logs`)**
  - Add `notification_logs` DB schema for tracking delivery attempts, HTTP status codes, error messages, and retry counts.
  - Implement async worker task queue offloading delivery routines.

- [ ] **Unit 5: User Settings & Product Notification Management UI**
  - Build `/user/settings/notifications` template and route for personal destinations/subscriptions.
  - Build `/products/{product_id}/settings/notifications` template and route for team destinations/subscriptions.
  - Implement **Test Ping** button (`POST /api/notifications/destinations/{id}/test`).

- [ ] **Unit 6: Astro Starlight Documentation Guide**
  - Add `docs/starlight/src/content/docs/guides/notifications.md`.

---

## 2. Scanner & Credential Vault Features

- [x] **Single Asset Re-run (Per-Widget Trigger)**
  - **Feature**: Allow users to click a **⚡ Scan** button on an individual scanner widget (Trivy, Semgrep, or Snyk) or asset row to re-run scans for a single release asset without re-scanning all assets in the release.
  - **Tasks**:
    1. Add single asset scan API endpoint (`POST /api/assets/{id}/scans?scanner=...`). ✅
    2. Add UI button trigger on scanner status widgets in `release_assets_table.html`. ✅
    3. Update Starlight documentation (`docs/starlight/src/content/docs/guides/scanners.md`). ✅

- [ ] **Git SSH Keys (OpenBao Credential Type)**
  - **Feature**: Support storing and injecting private SSH deploy keys in OpenBao Vault for cloning private Git repositories during Semgrep and Snyk scans.
  - **Tasks**:
    1. Add `ssh_key` credential schema and OpenBao storage handler in `src/rover/vault.py`.
    2. Update UI credential creation modal in `src/rover/templates/admin_credentials.html`.
    3. Inject SSH private keys into git worker process environments (`GIT_SSH_COMMAND`).
    4. Update Starlight documentation (`docs/starlight/src/content/docs/guides/vault-credentials.md`).
