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
- **How It Works**: Before launching containerized scanners, R.O.V.E.R. resolves the repository target ref (`git_ref` or `HEAD`) to its 40-character Git commit SHA-1 hash via `git ls-remote`. If a successful (`completed`) scan job within the configured Time-To-Live (TTL) window already exists for the exact same scanner name and commit SHA-1, R.O.V.E.R. reuses the existing scan report.
- **Cache Duration & Expiration**:
  - **Configurable TTL**: Defaults to **8 hours**. The cache retention window is fully configurable via `[scanner.cache_ttl_hours]` in `config.toml` (or via the Web UI at `/config`).
  - **Automatic Expiration**: Scan results older than `cache_ttl_hours` (8 hours by default) expire automatically. Re-running a scan on an asset whose cached results have expired will trigger a fresh scanner container execution, picking up newly published CVE vulnerability definitions or updated rule sets even if the Git commit SHA-1 remains unchanged.
- **Cache Invalidation & Triggers**:
  - Pushing new commits to the repository/branch updates the commit SHA-1, automatically triggering a fresh scan.
  - Required API tokens (such as Snyk tokens) are validated *before* cache lookup. If authentication or credentials are invalid or missing, cache lookups are bypassed and an explicit failure is reported.

### End-of-Life (EOL) Lifecycle Caching
- **What is Cached**: Release dates, End-of-Life status, and LTS flags fetched from `endoflife.date`.
- **How It Works**: EOL lifecycle records for major components (e.g., `postgresql 17`, `python 3.12`) are stored in the local database (`eol_cache`).
- **Cache Duration**: **Persistent local cache** per component version string to minimize external network calls and avoid API rate limits.

---

## Updating Scanner Versions

When upstream scanner updates (e.g., Trivy or Semgrep releases) are published, R.O.V.E.R. automatically notifies system administrators with a `scanner_update` alert.

### How to Update Scanner Configurations

1. **Inspect Upstream Release Notes**: Click **🔗 Inspect Release Notes** in the alert or visit the upstream scanner repository on GitHub to verify breaking changes, bug fixes, and release digests.
2. **Navigate to ROVER Configuration**:
   - Go to the **Configuration** page in the ROVER Web UI (`/config`).
   - Or edit your deployment configuration file (`rover.toml`).
3. **Update Image Parameter**:
   - Under the `[scanners]` section, update the target image parameter to the new version tag or pinned digest.
   - For Trivy: Update `[scanners.trivy_image]` (e.g., `aquasec/trivy:0.74.0` or `aquasec/trivy@sha256:...`).
   - For Semgrep: Update `[scanners.semgrep_image]` (e.g., `semgrep/semgrep:1.16.0` or `semgrep/semgrep@sha256:...`).
4. **Save Configuration**: Click **Save Changes** in the Web UI or restart the service stack if modifying `rover.toml`.
5. **Verify Scan Execution**: Future scan runs will automatically invoke the updated scanner container version.

---

### Security Best Practice: Pinning SHA256 Image Digests

While mutable tags like `:0.74.0` specify a release version, tag references can theoretically be overwritten or tampered with in image registries.

#### Advantages of Digest Pinning (`@sha256:...`)
- **Immutability & Integrity**: A cryptographic `sha256` digest permanently references the exact content-addressable image manifest. It cannot be altered even if the registry tag is updated or overwritten.
- **Supply Chain Security**: Prevents image spoofing, accidental downstream tag updates, and dependency confusion attacks.
- **Reproducibility**: Guarantees identical scanner environments across all ROVER deployments and automated CI/CD pipelines.

#### How to Find the SHA256 Image Digest
You can obtain the `sha256` digest for an updated scanner image using any of the following methods:

1. **GitHub Release Notes & Signatures**: Upstream releases (such as Trivy GitHub Releases) publish official release provenance files (`checksums.txt`, Cosign signatures, or build attestations) containing the cryptographic SHA-256 digests.
2. **Container Registry UI**: On GitHub Container Registry (GHCR) or Docker Hub, navigate to the image tag details page (e.g., `ghcr.io/aquasecurity/trivy` or `hub.docker.com/r/aquasec/trivy`) to view the published `Digest` SHA-256 hash.
3. **CLI Inspection via Docker**:
   Pull the updated image tag locally and inspect its repository digest:
   ```bash
   docker pull aquasec/trivy:0.74.0
   docker inspect --format='{{index .RepoDigests 0}}' aquasec/trivy:0.74.0
   # Output: aquasec/trivy@sha256:a1b2c3d4e5...
   ```
4. **CLI Inspection via `crane` or `skopeo`**:
   Inspect the digest directly from the registry without pulling the image layers:
   ```bash
   crane digest aquasec/trivy:0.74.0
   ```

