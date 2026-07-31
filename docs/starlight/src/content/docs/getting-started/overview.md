---
title: Platform Overview
description: Learn about R.O.V.E.R. concepts, user workflows, Products, Releases, and Assets.
---

**R.O.V.E.R. (Release Oriented Vulnerability Evaluation & Reporting)** is an enterprise vulnerability evaluation platform designed to assess release packages, container images, source repositories, and third-party dependencies before deployment.

---

## Key Domain Concepts

R.O.V.E.R. organizes security evaluation around four primary domain entities:

### 1. Products
A **Product** represents a top-level software system or application (e.g., *ROVER Core*, *E-Commerce Engine*). Products group software releases, manage recurring scan schedules, and control team permissions (`admin`, `read_write`, `read`).

### 2. Releases
A **Release** represents a specific versioned snapshot of a product (e.g., `v1.4.0`, `2026.07-rc1`). Each release aggregates target assets to be audited and tracks overall pass/fail vulnerability status.

### 3. Release Assets
**Release Assets** are the concrete artifacts evaluated by security scanners:
- **Git Repositories**: Source code repositories evaluated for code security vulnerabilities (SAST) and open-source package dependencies (SCA).
- **Container Images**: Docker/OCI container images evaluated for OS package vulnerabilities and container security risks.

### 4. Automated Evaluations
**Automated Evaluations** are background scanning tasks triggered manually or via cron schedules. They execute security scanners in parallel, record live progress updates, and generate consolidated reports.

### 5. Event-Driven Notifications & EOL Warnings
**Notification Rules** connect scan lifecycle events (`vulnerability.found`, `scan.completed`, `scan.failed`, `eol.warning`) to multi-channel transport destinations (Webhooks, Slack, SMTP, AWS SES) with multi-recipient targeting. Learn more in the [Event-Driven Notifications Guide](../guides/notifications/).

---

## User Evaluation & Security Workflow

```
+-------------------------------------------------------------------------+
|                         1. Define Product & Release                     |
|           Create a product and tag versioned release snapshots          |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                       2. Configure Target Assets                        |
|   Add Git Repositories, Container Images, and OpenBao Vault Credentials |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                     3. Run or Schedule Evaluations                      |
|    Trigger instant evaluations or set recurring automated cron schedules|
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                  4. Monitor Progress & Inspect Reports                  |
| Track real-time progress widgets and analyze unified vulnerability views |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                 5. Dispatch Event-Driven Notifications                  |
| Send real-time alerts via Webhook, Slack, SMTP Email, or AWS SES        |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                      6. Integrate CI/CD Pipelines                       |
|   Send build metadata automatically via REST API and API Tokens         |
+-------------------------------------------------------------------------+
```
