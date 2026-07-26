---
id: "202607260846"
type: Concept
title: ROVER Scanner Plugin Specification
description: Technical protocol and lifecycle interface for ROVER multi-scanner integration.
created: "2026-07-26T08:46:00Z"
updated: "2026-07-26T08:46:00Z"
tags:
  - rover/architecture
  - scanner/plugin-spec
status: stable
stale_after: "2027-01-01"
aliases:
  - ScannerPlugin Protocol
  - ROVER Scanner Architecture
---

# ROVER Scanner Plugin Specification

> **Summary**: The `ScannerPlugin` protocol defines a lightweight, extensible interface for adding security scanner engines (Trivy, Semgrep, EOL, Helm) to the ROVER vulnerability platform.

## 1. Overview

ROVER decouples scan execution from background worker threads by standardizing scanner integrations as python `Protocol` implementations. Any scanner engine must conform to the `ScannerPlugin` protocol defined in `rover.plugins.base`.

---

## 2. Protocol Interface Definition

```python
class ScannerPlugin(Protocol):
    """Protocol definition for all ROVER scanner plugins."""

    name: str
    supported_asset_types: set[str]

    def can_handle(self, target_type: str) -> bool:
        """Returns True if this plugin can process the specified target_type."""
        ...

    def scan(
        self,
        target_url: str,
        git_ref: str | None = None,
        target_type: str = "repo",
    ) -> ScanResult:
        """Executes a scan against the target and returns a ScanResult."""
        ...
```

---

## 3. Standard Result Data Model (`ScanResult`)

All scanner plugins return a standardized `ScanResult` container:

| Field | Type | Description |
| :--- | :--- | :--- |
| `results` | `dict[str, Any]` | Raw JSON payload output by the scanner engine. |
| `resolved_commit` | `str \| None` | Full SHA-1 commit hash resolved during git clone or scan. |
| `resolved_tags` | `str \| None` | Comma-separated git tags or container tag strings. |
| `source` | `str` | Provenance of output: `'fresh'` \| `'cached'` \| `'eol_api'` \| `'eol_cache'`. |
| `status` | `str \| None` | Execution status indicator (`'fresh'`, `'cached'`). |

---

## 4. Plugin Registry Mechanics

Plugins register into a global tuple registry inside `rover.plugins`:
1. `register_plugin(plugin: ScannerPlugin)`: Adds a new plugin instance.
2. `list_plugins() -> Sequence[ScannerPlugin]`: Lists all registered plugins.
3. `get_plugin_for_job(target_type: str) -> ScannerPlugin`: Finds the plugin capable of handling `target_type` via `.can_handle()`.

---

## 5. Registered Implementations

- [[trivy-scanner-plugin|Trivy Scanner Plugin]]: Container & dependency CVE vulnerability scanner.
- [[semgrep-scanner-plugin|Semgrep Scanner Plugin]]: Static application security testing (SAST).
- **Helm Scanner Plugin**: Helm chart import & container discovery.
- **EOL Component Scanner Plugin**: End-of-Life software lifecycle auditing.

---

## 6. Parent Index
- [[scanners-moc|ROVER Scanners Map of Content]]
