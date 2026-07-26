---
id: "202607260848"
type: Concept
title: Semgrep SAST Scanner Plugin
description: Static Application Security Testing (SAST) scanner plugin using Semgrep and ephemeral Docker volume isolation.
created: "2026-07-26T08:48:00Z"
updated: "2026-07-26T08:48:00Z"
tags:
  - rover/scanner
  - scanner/semgrep
  - security/sast
status: stable
stale_after: "2027-01-01"
aliases:
  - Semgrep Scanner
  - SemgrepScannerPlugin
---

# Semgrep SAST Scanner Plugin

> **Summary**: Implementation of [[rover-scanner-plugin-specification|ScannerPlugin]] that conducts static analysis (SAST) of repository source code using Semgrep inside isolated Docker volume mounts.

## 1. Capability & Asset Types

- **Plugin Name**: `semgrep`
- **Supported Asset Types**: `semgrep` (Repository source code scans)

---

## 2. Key Mechanisms & Execution Flow

1. **Volume Isolation & Source Cloning**:
   - Generates a unique ephemeral Docker volume (`rover-semgrep-clone-<uuid>`).
   - Launches an `alpine/git` container to clone the target repository into `/src` inside the shared volume using OpenBao authenticated credentials.
   - Handles branch checkout or explicit commit SHA checkout (`git checkout <commit_sha>`).

2. **Commit Hash Caching Strategy**:
   - Captures exact commit SHA via `git rev-parse HEAD`.
   - Semgrep scan results are cached by SHA-1 commit hash. Re-scans for un-changed commits reuse cached findings without re-triggering container execution.

3. **Ephemeral Container Execution**:
   - Launches `semgrep/semgrep` via `testcontainers`, mounting the clone volume to `/src` in read-only mode (`ro`).
   - Executes command: `semgrep scan /src --json --no-git-ignore --config auto`.

4. **Volume Cleanup**:
   - Parses stdout for JSON findings.
   - Cleans up and forcefully removes the temporary Docker volume after scan completion.

---

## 3. Related Concepts & Resources
- **Plugin Specification**: [[rover-scanner-plugin-specification]]
- **Upstream Tool Reference**: [[semgrep-sast]]
- **Index**: [[scanners-moc]]
