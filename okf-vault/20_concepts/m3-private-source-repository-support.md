---
id: "202607261119"
type: Feature
title: Private Source Repository Support
milestone: "M3"
feature_status: completed
dependencies:
  - M1
created: "2026-07-26T11:19:00Z"
updated: "2026-07-26T15:50:00Z"
tags:
  - roadmap/feature
  - roadmap/m3-private-git
  - status/completed
status: stable
stale_after: "2027-01-01"
aliases:
  - Milestone 3
  - Private Git Support
---

# Milestone 3: Private Source Repository Support (Completed)

> **Summary**: Allows ROVER to clone and scan private Git repositories by injecting saved credentials at clone time.

## 1. Feature Sub-components & Requirements

### 3.1 · Git Credential Injection
- Add `git_token` credential type to the Credential Vault.
- Associate credentials with target git hostnames (e.g. `github.com`, `gitlab.myco.com`).
- Inject token via `GIT_ASKPASS` or authenticated HTTPS URL rewrites (`https://<token>@github.com/...`) during `alpine/git` execution in scanner plugins.
- **Security Rule**: Tokens MUST NOT be logged or persisted to disk.

### 3.2 · Private Helm Repository Pull
- Extend Helm chart loading (OCI and HTTP) to authenticate using a stored `helm_token` credential.
- Pass credentials to `helm pull` or `skopeo copy` commands.

## 2. Dependencies
- **Prerequisites**: [[m1-credential-management|M1 (Credential Management)]].
- **Enables**: [[m8-helm-chart-version-polling|M8 (Helm Polling)]], [[m9-release-reports-and-api|M9 (Release Reports & API)]].

## 3. Related Concepts & Indices
- [[rover-scanner-plugin-specification|ROVER Scanner Plugin Specification]]
- [[roadmap-moc|ROVER Roadmap Map of Content]]
