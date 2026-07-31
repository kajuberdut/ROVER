---
title: Event-Driven Notification System
description: Configure multi-channel notification destinations, OpenBao secret encryption, default system email gateways, custom event rules, and EOL lead time advance warnings.
---

R.O.V.E.R. connects security scan events (vulnerability detection, scan failures, scan completion, and advance EOL warnings) to multi-channel notification destinations using a decoupled transport and recipient architecture.

---

## Supported Notification Destinations

ROVER supports four pluggable transport types:

1. **Webhook (HTTP POST + HMAC-SHA256)**:
   - Delivers event payloads to custom HTTP endpoints.
   - Computes HMAC-SHA256 signatures in `X-Rover-Signature` using secrets encrypted in OpenBao Vault.
2. **Slack & MS Teams**:
   - Delivers interactive Slack Block Kit / MS Teams card payloads directly to team channels.
3. **SMTP Email**:
   - Sends HTML and text email alerts via STARTTLS (port 587) or SSL/TLS (port 465).
   - Host credentials and passwords are encrypted in OpenBao Vault.
4. **AWS SES**:
   - Delivers email notifications via AWS Simple Email Service (SES).

---

## Destination Management & Default Email Gateway

### System Destinations
System Admins manage server-wide transport destinations under **⚙️ Admin** → **📢 Destinations** (`/admin/notifications/destinations`).

- **OpenBao Vault Secret Encryption**: All sensitive credentials (HMAC keys, SMTP passwords, AWS Secret Access Keys) are automatically encrypted in OpenBao Vault at `kv/data/rover/notifications/destinations/{id}`.
- **Default System Email Gateway (`is_default`)**: Mark an SMTP or AWS SES destination as the **Default System Email Gateway**. The system ensures that at most one default email gateway is active. Standard users automatically inherit this default gateway for personal email subscriptions.
- **Destination Editing**: System Admins can click **✏️ Edit** on any destination to update hosts, ports, usernames, or secrets without breaking existing subscription rules. Leaving password fields blank preserves existing Vault credentials.

---

## Subscriptions & Multi-Recipient Rules

ROVER decouples transport gateways (destinations) from target recipients:

### Personal Notification Subscriptions
- Non-admin users navigate to **User Menu** → **Notifications** (`/user/settings/notifications`).
- Standard users can subscribe to personal email alerts. Their recipient target is locked to their registered user email address, delivered via the server's **Default System Email Gateway**.
- If no system email gateway has been configured by a System Admin, an informative warning alert (`⚠️ No System Email Gateway Configured`) instructs the user to contact an administrator.

### Product & Team Subscriptions
- Product Admins configure product notification rules under **Product Dashboard** → **Notifications** (`/products/{product_id}/settings/notifications`).
- Rules support **multi-user recipient targeting** (`recipient_user_subs`) AND/OR **custom email addresses** (`custom_recipient_emails`), delivering alerts to multiple team members simultaneously in a single delivery session.

---

## Notification Event Types & Severity Thresholds

Attach event rules to any active destination:

- **`vulnerability.found`**: Triggers when security vulnerabilities are detected during scans. Filter by minimum severity threshold (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `ALL`). The minimum severity dropdown applies exclusively to `vulnerability.found` events.
- **`scan.completed`**: Triggers upon successful completion of scanner jobs.
- **`scan.failed`**: Fires when scanner jobs encounter execution errors.
- **`eol.warning`**: Evaluates component EOL dates against specified advance warning lead times (e.g. 90, 120, 180 days).

---

## Local Development & Testing Stack (`poe dev`)

ROVER includes a local developer Compose stack ([docker/docker-compose.dev.yml](file:///home/giblesnot/code/ROVER/docker/docker-compose.dev.yml)) pre-provisioned with **Mailpit** (SMTP email capture) and **WebhookHub** (Webhook logging, inspection, and replay).

### 1. Launch Dev Stack
Run the Poe task runner to provision certificates, OpenBao secrets, and launch all service containers:

```bash
poe dev
```

To stop the dev stack when finished:
```bash
poe dev-down
```

### 2. Testing SMTP Email Notifications (Mailpit)

- **Web UI**: Open [https://mail.rover.local](https://mail.rover.local) (or [http://localhost:8025](http://localhost:8025))
- **Configure SMTP Destination in ROVER**:
  1. Navigate to **⚙️ Admin** → **📢 Destinations** (`/admin/notifications/destinations`).
  2. Click **+ Add Destination** and select **SMTP Email**.
  3. Fill out the fields using the Mailpit dev credentials below:

```yaml
# Mailpit Dev SMTP Connection Info
Name: Mailpit Dev SMTP
SMTP Host: mailpit
Port: 1025
SMTP Username: rover
SMTP Password: 8sNqZn8Ilq1Qwt2iPJcoEQ
From Email Address: noreply@rover.local
Set as Default System SMTP Gateway: true
```

  4. Click **Save Destination**.
- **Send Test Ping**: Click **⚡ Test Ping** on the new Mailpit destination card to send an instant test email. Switch to the Mailpit browser tab to inspect the HTML & plaintext message headers and content.
- **Test Personal User Subscriptions**: Log in as a standard user, visit `/user/settings/notifications`, and create a rule. The rule will automatically bind to `Mailpit Dev SMTP`!

### 3. Testing Webhook Notifications (WebhookHub)

- **Web UI**: Open [http://localhost:3000](http://localhost:3000)

```yaml
# WebhookHub Admin Credentials
Email: admin@rover.local
Password: UsqEOHshh7UOAcigr_8_bQ
```

- **Configure Webhook Destination in ROVER**:
  1. Navigate to **⚙️ Admin** → **📢 Destinations**.
  2. Click **+ Add Destination** and select **Webhook (HTTP POST + HMAC)**.
  3. Fill out the fields using the WebhookHub dev parameters below:

```yaml
# WebhookHub Dev Destination Connection Info
Name: WebhookHub Test Endpoint
Webhook URL: http://webhookhub:8080/hook/rover
HMAC Secret Key: my-dev-secret
```

  4. Click **Save Destination**.
- **Send Test Ping & Inspect Payloads**: Click **⚡ Test Ping** or trigger a product re-scan. Open WebhookHub to inspect incoming JSON POST payloads, HTTP headers, and verify the `X-Rover-Signature` HMAC-SHA256 signature token.

---

## Testing & Audit Logging

- **⚡ Test Ping**: Click **Test Ping** on any destination to send an instant test payload and verify transport connectivity.
- **Audit Logging**: Every notification dispatch attempt (timestamp, HTTP status code, recipient count, error tracebacks, and payload JSON) is recorded in the `notification_logs` database table.


