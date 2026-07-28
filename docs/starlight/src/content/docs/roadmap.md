---
title: Product Roadmap
description: Upcoming user-facing features and planned enhancements for R.O.V.E.R.
---

Overview of upcoming user-facing features and capability additions planned for R.O.V.E.R.

---

### Upcoming User Features

- **Multi-Channel Event Notifications**: Real-time alert delivery to Slack, Microsoft Teams, Webhooks, SMTP Email, and AWS SES for scan completions, failures, and critical findings.
- **Advance EOL Warning Alerts**: Configurable lead-time notifications (e.g. 90 or 120 days prior to End-of-Life dates) for software components and base images.
- **Per-User Subscriptions**: Individual notification preferences allowing users to subscribe to specific products, releases, or severity thresholds.
- **Private Repository Deploy Keys**: Store and manage private SSH deploy keys in OpenBao Vault for scanning private Git repositories.
- **Private Container Registry Authentication**: Store Docker Hub, AWS ECR, Google Artifact Registry, and Quay credentials for scanning private container images.
- **Vulnerability Triage & Status Management**: Mark findings as *False Positive*, *Mitigated*, or *Accepted Risk* directly within report views.
- **Release Pass/Fail Security Policy Gates**: Configure policy rules (e.g., "Block release if any Critical CVE exists") to enforce security standards.
