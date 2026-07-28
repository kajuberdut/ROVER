---
title: Security Scanners (Trivy, Semgrep, Snyk)
description: Overview of supported security scanners, target asset types, and how to manage scanner executions.
---

R.O.V.E.R. integrates three security scanners to evaluate container images, source repositories, and open-source software dependencies.

---

## Supported Scanners & Target Types

| Scanner | Target Asset | Primary Focus | Evaluated Artifacts |
| :--- | :--- | :--- | :--- |
| **Trivy** | Container Images | OS Vulnerabilities | System packages (apt, apk, yum), OS CVE ratings, fixed package versions. |
| **Semgrep** | Git Repositories | Code Security (SAST) | Source code patterns, hardcoded secrets, OWASP Top 10 vulnerabilities. |
| **Snyk** | Container Images & Git Repos | Dependencies (SCA) | Open-source package manifests (pip, npm, go.mod), vulnerable sub-dependencies. |

---

## Running & Managing Scans

### Triggering Scans
- **Full Release Evaluation**: Click **⚡ Run All Scanners** on the Release Dashboard to dispatch scans across all defined release assets.
- **Single Asset Re-run**: Click the **⚡ Scan** button on a specific scanner widget (Trivy, Semgrep, or Snyk) or in the asset action column to re-evaluate just that single asset without re-scanning all assets in the release.
- **REST API Endpoint**: Programmatically trigger single asset re-runs via `POST /api/assets/{release_asset_id}/scans?scanner={trivy|semgrep|snyk|all}`.

### Monitoring Scan Status
Scanner widgets on the Release Assets page display the current state of each evaluation:
- `Queued`: The scan request is waiting in line.
- `Running`: The scanner container is actively analyzing the asset.
- `Completed`: Analysis finished cleanly and findings are compiled.
- `Failed`: The scan encountered an error (click **Logs** to view details).

Widget status badges update automatically as scans complete. The elapsed time display (e.g., `14s (avg: 5s)`) shows current scan duration compared to previous runs on the same asset.
