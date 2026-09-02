# R.O.V.E.R. Project TODOs & Feature Roadmap

## 1. Event-Driven Notification System (Per-User, Multi-Channel & EOL Advance Warnings)

- [x] **Unit 1: Notification Destinations Schema & OpenBao Vault Integration**
  - Add `notification_destinations` DB schema supporting `user_id`, `product_id`, and `is_system` scope. ✅
  - Types: `webhook`, `slack`, `smtp`, `aws_ses`. ✅
  - Vault secret path helpers for storing `smtp_password`, `aws_secret_key`, `webhook_secret`. ✅

- [x] **Unit 2: Per-User & Product Rule Engine with EOL Lead Times**
  - Add `notification_rules` DB schema supporting event types (`scan.completed`, `scan.failed`, `vulnerability.found`, `eol.warning`), severity thresholds, and **`eol_warning_days`** (INTEGER lead time, e.g. 90, 120, 180 days). ✅
  - Create rule evaluation logic firing alerts when `days_remaining <= eol_warning_days`. ✅

- [x] **Unit 3: Pluggable Transports (Webhook, Slack/Teams, SMTP, AWS SES)**
  - Implement `WebhookTransport` (HTTP POST + HMAC-SHA256 headers). ✅
  - Implement `SlackTransport` (Block Kit payloads). ✅
  - Implement `SmtpTransport` (`smtplib` TLS/STARTTLS). ✅
  - Implement `AwsSesTransport` (AWS SES API delivery). ✅

- [x] **Unit 4: Async Dispatch Engine & Audit Log (`notification_logs`)**
  - Add `notification_logs` DB schema for tracking delivery attempts, HTTP status codes, error messages, and retry counts. ✅
  - Implement async worker task queue offloading delivery routines. ✅

- [x] **Unit 5: User Settings & Product Notification Management UI**
  - Build `/user/settings/notifications` template and route for personal destinations/subscriptions. ✅
  - Build `/products/{product_id}/settings/notifications` template and route for team destinations/subscriptions. ✅
  - Implement **Test Ping** button (`POST /api/notifications/destinations/{id}/test`). ✅

- [x] **Unit 6: Astro Starlight Documentation Guide**
  - Add `docs/starlight/src/content/docs/guides/notifications.md`. ✅

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

---

## 3. Centralized Vulnerability Ledger, Digest & Ignore Rules Engine

- [ ] **Unit 1: Centralized Vulnerability Ledger (`asset_vulnerabilities` table)**
  - Add unified DB schema `(id, asset_id, scanner_name, vulnerability_id, cve_id, package_name, installed_version, fixed_version, severity, status, first_seen_at, last_seen_at)`.
  - Ingest & normalize raw scan outputs from Trivy, Semgrep, and Snyk into the central ledger.
  - Track vulnerability lifecycle states (`active`, `resolved`, `ignored`).

- [ ] **Unit 2: Delta Ingestion & `vulnerability.new` Event Engine**
  - Compare scan findings against existing `asset_vulnerabilities` to detect newly introduced vulnerabilities (`first_seen_at == scan_timestamp`).
  - Fire `vulnerability.new` events containing only newly detected vulnerabilities, ignoring unchanged existing findings.

- [ ] **Unit 3: Consolidated Scan Digest & Cooldown Rate-Limiting**
  - Aggregate `vulnerability.new` findings into a single consolidated digest payload per scan run (e.g. Total New Count, Top CVEs, Direct Report Link).
  - Implement configurable cooldown windows (`cooldown_minutes`, e.g. 60 minutes) per destination/rule to prevent inbox flooding from rapid CI/CD scan triggers.

- [ ] **Unit 4: Vulnerability Triage & Ignore Rules UI**
  - Allow users/admins to mark vulnerabilities as `ignored` (false positive, risk accepted) with reason notes and optional expiration dates.
  - Exclude ignored vulnerabilities from notifications, posture metrics, and compliance reports.

---

## 4. Email Verification, Password Reset & Email-Only Users

- [x] **Unit 1: Email Address Confirmation Workflow**
  - Generate cryptographically signed verification tokens (`itsdangerous` / HMAC) with 24-hour expiration. ✅
  - Dispatch verification emails via SMTP/SES when an email destination or user address is added or updated. ✅
  - Implement `/confirm-email?token=...` route to verify deliverability and mark email addresses as `is_verified`. ✅
  - Require email verification before dispatching active email notifications. ✅

- [x] **Unit 2: Email Password Reset (Authelia Integration)**
  - Build `/forgot-password` and `/reset-password?token=...` routes and templates. ✅
  - Generate secure, single-use password reset tokens and send recovery links via SMTP/SES. ✅
  - Integrate password resets with Authelia session authentication and local account credentials. ✅

- [x] **Unit 3: "Email-Only" Users & Self-Service Unsubscribe Portal**
  - Add `email_only` user role (`role: "email_only"`) created for the sole purpose of receiving notification alerts. ✅
  - Dispatch verification email link automatically upon `email_only` user provisioning. ✅
  - Build restricted self-service subscription view (`/user/subscriptions`) allowing `email_only` users to view and remove themselves from subscriptions (with restricted access blocking access to scanner and product dashboards). ✅


