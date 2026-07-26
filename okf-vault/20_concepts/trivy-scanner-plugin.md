---
id: "202607260847"
type: Concept
title: Trivy Scanner Plugin
description: Container image and repository dependency CVE scanner plugin powered by Aqua Trivy.
created: "2026-07-26T08:47:00Z"
updated: "2026-07-26T08:47:00Z"
tags:
  - rover/scanner
  - scanner/trivy
  - vulnerability/cve
status: stable
stale_after: "2027-01-01"
aliases:
  - Trivy Scanner
  - TrivyScannerPlugin
---

# Trivy Scanner Plugin

> **Summary**: Implementation of [[rover-scanner-plugin-specification|ScannerPlugin]] that executes ephemeral Trivy container vulnerability scans across Git repositories and container images.

## 1. Capability & Asset Types

- **Plugin Name**: `trivy`
- **Supported Asset Types**: `repo`, `image`

---

## 2. Key Mechanisms & Execution Flow

1. **Target Inspection**:
   - For `repo` targets: Authenticates git credentials via OpenBao vault helper (`vault.get_authenticated_git_url`), clones the repository to a temporary directory, checks out `git_ref`, and captures `git rev-parse HEAD` and tags.
   - For `image` targets: Formats the image target string and resolves image digest SHA-256 via Skopeo inspect or Docker Registry v2 API.

2. **Ephemeral Container Execution**:
   - Uses `testcontainers` to launch the configured `aquasec/trivy` image.
   - Mounts persistent Docker volume `trivy-vulnerability-db-cache` to `/trivy-cache` for fast offline/cached CVE vulnerability DB access.
   - Mounts `/var/run/docker.sock` (read-only) for inspecting local Docker images.

3. **Update Notice Detection**:
   - Parses stderr/stdout logs using regex for notice strings: `Version vX.Y.Z of Trivy is now available, current version is vA.B.C`.
   - Automatically records an admin notification in ROVER database (`db.create_admin_notification`) when a newer Trivy version is released.

4. **Result Packaging**:
   - Extracts JSON output payload from stdout.
   - Returns a [[rover-scanner-plugin-specification|ScanResult]] containing parsed `Results` array, resolved commit hash, and tag strings.

---

## 3. Related Concepts & Resources
- **Plugin Specification**: [[rover-scanner-plugin-specification]]
- **Digest Pinning Policy**: [[container-image-digest-pinning|Container Image Digest Pinning Policy]]
- **Upstream Tool Reference**: [[aquasec-trivy]]
- **Security Advisory**: [[ghsa-69fq-xp46-6x23-trivy-supply-chain-advisory]]
- **Index**: [[scanners-moc]]
