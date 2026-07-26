# System Architecture: OKF Vault Blueprint for ROVER (v0.2 Standard)

This document specifies the architectural blueprint and operational mechanics of the `okf-vault` implementation for the **ROVER (Release Oriented Vulnerability Evaluation & Reporting)** platform. It builds directly upon the official [Open Knowledge Format (OKF) v0.2 Specification](file:///home/giblesnot/code/ROVER/okf-vault/00_meta/okf-spec-v0.2.md).

---

## 1. Architectural Purpose & Relationship to OKF Spec

While the [OKF v0.2 Specification](file:///home/giblesnot/code/ROVER/okf-vault/00_meta/okf-spec-v0.2.md) defines the universal, tool-agnostic protocol for representing knowledge, this **System Architecture** document describes the concrete folder hierarchy, frontmatter schema bindings, template conventions, and CLI tooling implemented in this vault for security vulnerability evaluation, release package assessments, and scanner integration.

### Core Architectural Principles
- **Strict OKF Compliance**: All notes mandate `type` in frontmatter and support OKF provenance, trust, and lifecycle fields.
- **Tool-Agnostic & Zero Lock-in**: Compatible with Logseq, VS Code, Antigravity CLI (AGY), static site generators, and custom parsers without vendor lock-in.
- **Deterministic File Tree**: Numeric folder prefixes (`00_meta` through `50_archive`) guarantee predictable navigation ordering across all operating systems.
- **Automated Quality Control**: Built-in CLI scripts (`scripts/validate_schema.py`) and AGY agent rules (`.gemini/rules/okf-compliance.md`) enforce schema validity before deployment or publishing.

---

## 2. Directory Hierarchy Blueprint

```
okf-vault/
├── 00_meta/                       # Structural metadata, schemas, and specifications
│   ├── okf-spec-v0.2.md           # Official OKF v0.2 specification copy
│   ├── schemas/                   # JSON Schema definitions
│   │   └── okf_schema_v0.2.json   # Frontmatter schema validator
│   └── templates/                 # Markdown templates for new note creation
│       ├── concept_template.md    # Template for atomic concepts (e.g. SAST, CVE Policy)
│       ├── resource_template.md   # Template for external references (e.g. Trivy, OpenBao)
│       ├── index_template.md      # Template for Maps of Content (MOCs)
│       └── log_template.md        # Template for daily logs
├── 10_inbox/                      # Landing zone for raw, un-triaged scan outputs (.gitkeep)
├── 20_concepts/                   # Atomized concepts & security definitions (.gitkeep)
├── 30_resources/                   # External references, scanners, & docs (.gitkeep)
├── 40_indices/                    # Maps of Content (MOCs) & navigation hubs (.gitkeep)
├── 50_archive/                    # Historical or deprecated concepts (.gitkeep)
├── .gemini/                       # Antigravity CLI integration directory
│   ├── AGENTS.md                  # Agent operating instructions
│   └── rules/                     # AGY enforcement rules
│       └── okf-compliance.md
├── scripts/                       # Vault utility scripts
│   └── validate_schema.py         # Python OKF frontmatter validator script
├── CONTRIBUTING.md                # Contributor & note creation guidelines
├── LICENSE                        # Apache 2.0 Open Source License
├── README.md                      # Knowledge base overview & quickstart
└── SYSTEM_ARCHITECTURE.md         # This architecture blueprint
```

---

## 3. Metadata Binding (OKF v0.2 Schema)

Notes in this vault inherit the OKF v0.2 frontmatter standard.

### Core Required & Optional Fields

```yaml
---
type: Concept                            # REQUIRED: Short string identifying note classification
id: "202607260830"                       # 12-digit timestamp identifier (YYYYMMDDHHMM)
title: "Trivy Container Vulnerability Scan" # Human-readable title
description: "Rules for container image CVE auditing." # One-line summary
created: "2026-07-26T08:30:00Z"          # ISO-8601 creation timestamp
updated: "2026-07-26T08:30:00Z"          # ISO-8601 last modified timestamp
tags: [security/vulnerability, scanner/trivy] # List of categorical tags
status: stable                           # draft | stable | deprecated (default: stable)
stale_after: "2026-12-31"                # Absolute YYYY-MM-DD re-verification date
aliases: ["Container CVE Scan"]          # Alternative titles
generated:                               # Provenance of content creation
  by: "reference_agent/gemini-2.5-pro"
  at: "2026-07-26T08:30:00Z"
verified:                                # Trust confirmation
  - by: "human:giblesnot"
    at: "2026-07-26T09:00:00Z"
---
```

---

## 4. Lifecycle & Staleness Logic

1. **Status Progression**:
   - `draft`: Security concept or policy is undergoing initial synthesis.
   - `stable`: Fully reviewed, reliable, and active (default if omitted).
   - `deprecated`: Outdated scanner policy or security rule. Preserved for query reproducibility. Moved to `50_archive/` or tagged appropriately.

2. **Staleness Handling**:
   - `stale_after`: ISO date (`YYYY-MM-DD`). Automated tools flag notes where `today >= stale_after` for mandatory review (e.g. annual security policy re-approval) without breaking link targets.

---

## 5. CLI & Agent Integration

This vault is pre-configured to work with the **Antigravity CLI (AGY)**:
- **Instructions**: `.gemini/AGENTS.md` provides prompt rules for AGY agents.
- **Enforcement Rules**: `.gemini/rules/okf-compliance.md` mandates YAML headers and file conventions.
- **Verification Utility**: Run `python3 scripts/validate_schema.py` to check vault health.
