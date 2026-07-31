---
title: Changelog & Release Notes
description: Recent updates, new user-facing features, and enhancements to R.O.V.E.R.
---

Summary of recent user-facing updates and product enhancements.

---

### Recent Additions

- **Notification Destinations**: Multi-channel delivery destination management supporting SMTP Email, Webhook (HMAC-SHA256), AWS SES, MS Teams, and Slack.
- **Notification Rules**: Event rule configuration supporting `vulnerability.found` (with severity filtering), `scan.completed`, `scan.failed`, and `eol.warning` (with advance lead-time thresholds).
- **Single Asset Re-runs**: Trigger focused security scans for individual container images or source repositories directly from scanner status widgets without re-evaluating the entire release.
- **Interactive Swagger UI**: Explore and test R.O.V.E.R. public REST API endpoints directly in your browser at `/api/docs`.
- **Automated Scan Schedules**: Set up recurring background scan schedules on products and releases using flexible cron patterns and execution history logs.
- **Multi-Scanner Security Suite**: Comprehensive release evaluation combining OS vulnerabilities (Trivy), static code analysis (Semgrep), and dependency scanning (Snyk).
- **Per-Asset Time & Health Widgets**: Monitor real-time scan progress, historical run duration averages (`14s (avg: 5s)`), and vulnerability risk indicators per asset.
- **Unified Vulnerability Reports**: Deep-linked report views with multi-scanner tab navigation (`?tab=trivy`, `?tab=semgrep`, `?tab=snyk`) and container-to-repository cross links.
- **OpenBao Credential Vault**: Secure management for scanner API tokens, registry credentials, and deploy keys.
