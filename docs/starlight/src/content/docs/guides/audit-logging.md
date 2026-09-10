---
title: Security Audit Logging & Compliance
description: Comprehensive reference for ROVER's hybrid security audit logging system, REST API querying, SIEM log shipping, and schema reference.
---

R.O.V.E.R. implements a **Hybrid Security Audit System** that records all administrative actions, configuration changes, user governance events, vulnerability triage decisions, and scheduled scan executions.

Audit events are dual-persisted:
1. **Database Persistence**: Written to the `audit_logs` SQL table for historical querying, API access, and in-app compliance reporting.
2. **SIEM / Log Stream Emission**: Emitted as single-line structured JSON logs over standard output under the `rover.audit` logger for real-time SIEM shipping (Datadog, Splunk, Elastic/Kibana, Vector, OpenSearch).

---

## 🔒 Audited System Events

ROVER automatically logs structured audit entries for critical operations across the platform:

| Event Category | Action String | Description & Trigger |
| :--- | :--- | :--- |
| **System Configuration** | `config.update` | Modifications to `config.toml` or scanner container image pins via Web UI or API. |
| **User Governance** | `user.promote` | Changing user system roles (`system_admin`, `viewer`, `email_only`). |
| **User Governance** | `user.invite` / `user.delete` | Generating user invitations or purging user accounts. |
| **API Tokens** | `token.create` / `token.revoke` | Creating or revoking API authentication tokens. |
| **Vulnerability Triage & VEX** | `vulnerability.triage` | Applying triage status (*Accepted Risk*, *False Positive*, *Mitigated*) with justification. |
| **VEX Approvals** | `vex.approve` / `vex.reject` | Approving or rejecting VEX extension proposals. |
| **Scan Schedules** | `scheduled_scan.create` / `update` / `delete` | Modifying cron schedules or dispatching manual scan executions. |
| **Notification Destinations** | `notification_destination.create` / `delete` | Configuring Webhook, Slack, Email, or OpenBao notification channels. |
| **Notification Rules** | `notification_rule.create` / `delete` | Modifying severity thresholds, target products, or recipient email subscriptions. |

---

## 🔍 Recommended Ways to Review Audit Logs

ROVER provides three official methods for reviewing audit events depending on your operational needs:

### Method 1: REST API Endpoint (`GET /api/admin/audit_logs`)

System Administrators (`system_admin` role) can query historical audit logs via the REST API with built-in parameter filtering and pagination.

#### Endpoint Specification:
```http
GET /api/admin/audit_logs
Authorization: Bearer rov_tok_your_admin_token...
```

#### Query Parameters:

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `action` | `string` | *(Optional)* | Filter by action type (e.g. `config.update`, `user.promote`, `vulnerability.triage`). |
| `resource_type` | `string` | *(Optional)* | Filter by resource type (e.g. `config`, `user`, `vulnerability`, `scheduled_scan`, `notification_destination`). |
| `resource_id` | `string` | *(Optional)* | Filter by exact target resource identifier (e.g. `usr_123`, `vuln_456`). |
| `user_sub` | `string` | *(Optional)* | Filter by subject identifier or email of the actor. |
| `limit` | `integer` | `100` | Maximum number of log records to return (1-500). |
| `offset` | `integer` | `0` | Offset for pagination. |

#### Example API Request:
```bash
# Fetch recent configuration changes
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://rover.local/api/admin/audit_logs?resource_type=config&limit=20"
```

#### Example JSON Response:
```json
{
  "audit_logs": [
    {
      "id": "8f3b2c1a-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
      "timestamp": "2026-09-09T21:41:27.123456+00:00",
      "action": "config.update",
      "resource_type": "config",
      "resource_id": "config.toml",
      "user_sub": "usr_admin_999",
      "user_email": "admin@example.com",
      "changes": {
        "scanners.trivy_image": "aquasec/trivy:0.74.0@sha256:cffe3f5161a47a6823fbd23d985795b3ed72a4c806da4c4df16266c02accdd6f"
      },
      "ip_address": "192.168.1.50"
    }
  ],
  "count": 1
}
```

---

### Method 2: SIEM & Log Aggregator Integration (`rover.audit` stdout stream)

For enterprise security operations (SOC), all audit records are simultaneously written to container standard output (`stdout`) under the dedicated logger name `rover.audit`.

#### Live Log Tail via Poe Task Runner:
```bash
poe logs | grep '"event":"audit"'
```

#### Log Line Format:
Logs are emitted as single-line, unescaped JSON objects matching standard SIEM ingestion patterns:

```json
{"event": "audit", "audit_id": "8f3b2c1a-4d5e-6f7a-8b9c-0d1e2f3a4b5c", "timestamp": "2026-09-09T21:41:27.123456+00:00", "action": "user.promote", "resource_type": "user", "resource_id": "usr_42", "user_sub": "admin_sub", "user_email": "admin@rover.local", "changes": {"old_role": "viewer", "new_role": "system_admin"}, "ip_address": "10.0.0.12"}
```

#### Supported SIEM Integrations:
- **Datadog / Splunk / Elastic Search / OpenSearch**: Configure log parsers to target log lines where `event == "audit"`.
- **Vector / FluentBit / Logstash**: Route logs with `logger == "rover.audit"` directly to cold compliance storage or alert pipelines.

---

### Method 3: Direct Database Inspection (`audit_logs` SQL Table)

System administrators with database access (or running local development setups) can query the `audit_logs` table directly.

#### Table Schema (`audit_logs`):

```sql
CREATE TABLE audit_logs (
    id VARCHAR(36) PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    user_sub VARCHAR(255),
    user_email VARCHAR(255),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(255),
    changes_json TEXT,
    ip_address VARCHAR(45)
);
```

#### SQL Query Examples:

```sql
-- 1. Review all user role changes and promotions
SELECT created_at, user_email, action, resource_id, changes_json
FROM audit_logs
WHERE action LIKE 'user.%'
ORDER BY created_at DESC;

-- 2. Audit all vulnerability triage decisions
SELECT created_at, user_email, resource_id, changes_json
FROM audit_logs
WHERE action = 'vulnerability.triage'
ORDER BY created_at DESC;
```

---

## ⚙️ Audit Logging Architecture & Data Integrity

- **Automated Context Capture**: Requests passing through authenticated API or Web UI endpoints automatically extract user identity (`user_sub`, `user_email`) and remote client IP address (`ip_address`).
- **Indexed Queries**: Database indexes (`idx_audit_logs_action`, `idx_audit_logs_resource`, `idx_audit_logs_user`, `idx_audit_logs_created`) ensure sub-millisecond query response times even with high log volumes.
- **Immutability**: Audit log entries are insert-only records. ROVER APIs do not expose endpoints for editing or deleting audit log history.
