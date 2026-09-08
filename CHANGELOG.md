# Changelog

All notable changes to the R.O.V.E.R project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **OpenVEX Document Engine & REST API**: Implemented OpenVEX format support with standard `@context` (`https://openvex.dev/ns/v0.2.0`), vulnerability statements, justification codes (`vulnerable_code_not_in_execute_path`, etc.), and public document endpoints (`GET /api/vex/doc/{hash}`).
- **Software Bill of Materials (SBOM) & Triage System**: Added database schema and API routes for recording per-asset SBOM components, tracking vulnerability triage history, and handling automatic decision expiration.
- **Consolidated Database Migrations**: Merged all incremental schema definitions into a unified single initial migration (`migrations/0001_initial_schema.sql`).
- **Multi-Scanner Architecture & Parallel Execution**: Added parallel multi-process scanning engine (`Trivy`, `Semgrep`, `Snyk`) executing scanner containers concurrently.
- **Snyk Security Scanner Integration**: Integrated Snyk Security CLI scanner for open-source dependency vulnerability detection and container analysis.
- **OpenBao Credential Vault**: Integrated OpenBao Vault for securely storing and managing scanner API tokens, registry credentials, and private Git SSH keys.
- **Per-Asset Scanner Widgets & Execution Time Tracking**: Redesigned the Release Assets view with dedicated per-scanner widgets, real-time progress bars, and historical duration tracking (`"14s (avg: 5s)"`).
- **Unified Report Viewer & Deep-Linking**: Added unified multi-scanner report views with direct tab navigation (`?tab=snyk`, `?tab=semgrep`, `?tab=trivy`) and cross-linked container-to-repository vulnerability views.
- **Automated Scan Scheduler & Audit Log Management**: Added background scan scheduler with cron frequency presets, responsive UI, manual triggers, and audit logs.
- **OpenAPI 3.0 Auto-Documentation & Interactive Swagger UI**: Added `/api/openapi.json` generator and interactive Swagger UI explorer at `/api/docs` and `/api/swagger`.
- **Astro Starlight User Documentation Suite**: Integrated Astro Starlight user documentation under `/docs/guide/`, built via Docker container (`node:24-alpine`).
- **RFC 6750 Authentication Standardization**: Standardized public REST API authentication on standard `Authorization: Bearer <token>` headers.
- **Notification Destinations & Rules**: Multi-channel destinations (SMTP, Webhook HMAC-SHA256, AWS SES, MS Teams, Slack) and configurable event rules.
- **Single Asset Re-run**: Added `POST /api/assets/{id}/scans` endpoint and ⚡ Scan action buttons on individual scanner widgets.
- **Email Address Confirmation & Self-Service Password Reset**: Signed token email confirmation and Authelia/local password reset workflows.
- **Email-Only User Role & Subscriptions Portal**: Added `email_only` role with middleware access control enforcing restricted portal navigation to `/user/subscriptions`.

### Changed / Refactored
- **Code Quality & Dead Code Cleanup**: Narrowed broad exception blocks to explicit exception types with descriptive inline comments; refactored high-cyclomatic-complexity scanner functions (`scan()` in `trivy.py`) into modular helpers.
- **Circular Dependency Elimination**: Resolved circular imports between `rover.db`, `user_invites`, and `tokens` via lazy module loading.



