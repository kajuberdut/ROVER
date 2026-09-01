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

---

## Scan Caching & Retention

R.O.V.E.R. uses intelligent caching to optimize scan performance and prevent unnecessary re-execution of containerized scanners or external API requests.

### Git Commit Hash Caching (Scanners)
- **What is Cached**: Security scan results for Trivy, Semgrep, and Snyk for repository assets.
- **How It Works**: Before launching containerized scanners, R.O.V.E.R. resolves the repository target ref (`git_ref` or `HEAD`) to its 40-character Git commit SHA-1 hash via `git ls-remote`. If a successful (`completed`) scan job already exists in the database for the exact same scanner name and commit SHA-1, R.O.V.E.R. reuses the existing scan report.
- **Cache Duration**: **Permanent per Git Commit SHA-1**. Because Git commits are immutable by design, scan findings for a specific commit SHA-1 remain valid indefinitely.
- **Cache Invalidation & Triggers**:
  - Pushing new commits to the repository/branch updates the commit SHA-1, automatically triggering a fresh scan.
  - Required API tokens (such as Snyk tokens) are validated *before* cache lookup. If authentication or credentials are invalid or missing, cache lookups are bypassed and an explicit failure is reported.

### End-of-Life (EOL) Lifecycle Caching
- **What is Cached**: Release dates, End-of-Life status, and LTS flags fetched from `endoflife.date`.
- **How It Works**: EOL lifecycle records for major components (e.g., `postgresql 17`, `python 3.12`) are stored in the local database (`eol_cache`).
- **Cache Duration**: **Persistent local cache** per component version string to minimize external network calls and avoid API rate limits.
