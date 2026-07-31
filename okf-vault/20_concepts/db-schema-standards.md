---
id: "202607292200"
type: Concept
title: Database Schema & Type Standards
created: 2026-07-29
updated: 2026-07-29
tags:
  - concept/database
  - architecture
  - standards
  - rover/db
status: stable
stale_after: 2027-07-29
aliases:
  - ROVER Database Standards
  - Database Schema Conventions
---

# Database Schema & Type Standards

> **Summary**: Architectural conventions and data modeling standards for R.O.V.E.R. database schema migrations (`migrations/`), SQLAlchemy Core representations (`src/rover/db/schema.py`), and OpenBao Vault credential references.

---

## 1. Column Types & Enumerated Values

### Enums & Status Fields: `VARCHAR` + Python `StrEnum`

ROVER uses **`VARCHAR(50)` (or `VARCHAR(255)`)** for enumerated types, categories, scopes, and status values, rather than native PostgreSQL `CREATE TYPE ... AS ENUM`.

**Rationale**:
1. **Multi-Database & Test Compatibility**: Allows tests and local dev environments to run seamlessly against SQLite or PostgreSQL without custom dialect branch logic.
2. **Transaction-Safe Migrations**: Adding new enum values (e.g. a new scanner status or notification event type) in native Postgres `ENUM` requires `ALTER TYPE ... ADD VALUE`, which cannot execute inside multi-statement migration transactions in PostgreSQL.
3. **Application-Level Validation**: Enforce strict typing, validation, and autocomplete using Python `StrEnum` (or `enum.Enum`) in the corresponding domain DB modules (e.g., `src/rover/db/notification_rules.py`).

**Example**:
```python
from enum import StrEnum

class NotificationEventType(StrEnum):
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    VULNERABILITY_FOUND = "vulnerability.found"
    EOL_WARNING = "eol.warning"

class NotificationSeverity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    ALL = "ALL"
```

---

## 2. Flexible Configuration & JSON Metadata

Use `TEXT` / `VARCHAR` columns with `config_json` or `metadata_json` names (defaulting to `'{}'`) for storing structured, non-sensitive provider configuration:
- **`config_json`**: Transport settings (e.g., SMTP host/port/username, Slack channel, Webhook URL, AWS region).
- **`metadata_json`**: Ad-hoc trigger context (e.g., commit hashes, versions, scanner warning details).

---

## 3. Secret Storage & OpenBao Vault References

**Rule**: **Never store plaintext secrets, API keys, HMAC keys, or passwords in database columns.**

- Store non-sensitive metadata and configuration in the database table (`credentials`, `notification_destinations`).
- Store sensitive values in **OpenBao Vault** under `kv/data/rover/...`.
- The database record stores a `vault_secret_path` string referencing the OpenBao path.
- At runtime, use the appropriate DB/Vault helper functions (`get_destination_unmasked_secret()`, `get_unmasked_secret()`) to retrieve decrypted secrets in memory for worker execution.

---

## 4. Foreign Keys & Cascading Deletes

- Use explicit foreign keys referencing parent entities (`products(id)`, `releases(id)`, `users(sub)`).
- Include `ON DELETE CASCADE` for parent-child ownership relationships (e.g., deleting a product cleans up its rules, assets, scheduled scans, and destinations).

---

## 5. Related Architecture Notes

- [[a3-database-layer-decomposition|Architecture Target A3: Database Access Layer]]
- [[a4-schema-migrations|Architecture Target A4: SQL Schema Migrations]]
- [[notification_system_architecture|Notification System Architecture]]
- [[openbao-secret-injection|OpenBao Secret Injection]]
