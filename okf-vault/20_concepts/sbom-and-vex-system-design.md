---
id: "202609030848"
type: Concept
title: Software Bill of Materials, VEX, and Automated Triage System Architecture
created: "2026-09-03T08:48:00Z"
updated: "2026-09-03T08:48:00Z"
tags:
  - concept/architecture
  - rover/sbom
  - rover/vex
  - rover/triage
status: stable
stale_after: "2027-09-03"
aliases:
  - SBOM and VEX System Design Blueprint
  - Software Supply Chain Architecture
---

# Architectural Blueprint for Software Bill of Materials, Vulnerability Exploitability eXchange, and Automated Triage in R.O.V.E.R.

## System Architecture & Operational Context

The Release Oriented Vulnerability Evaluation & Reporting (ROVER) platform is architected as an asynchronous, container-native security evaluation framework. Its core stack comprises a Python Falcon ASGI application, a PostgreSQL database managed via the shipship SQL migration framework, an OpenBao secrets engine for dynamic credential injection, Authelia OIDC identity controls, and an ephemeral Docker worker pool managed through Testcontainers. The system currently orchestrates multi-scanner evaluations across container images and Git repositories using Aqua Security’s Trivy, Semgrep SAST, and Snyk.  
While ROVER successfully provides point-in-time vulnerability discovery, its existing evaluation engine processes security findings in an ephemeral manner. Scans produce raw findings tied to specific asset runs, but the platform lacks a persistent, queryable inventory of underlying software dependencies, a mechanism to record human triage dispositions, and a standardized method to emit or consume Vulnerability Exploitability eXchange (VEX) statements.  
Driven by international software supply chain mandates—such as United States Executive Order 14028, the European Union Cyber Resilience Act, and National Telecommunications and Information Administration (NTIA) minimum element requirements—modern DevSecOps platforms must maintain an authoritative, versioned inventory of all compiled software components. Transforming ROVER into a supply chain security platform requires introducing three interconnected capabilities:

> 1. **Software Bill of Materials (SBOM) Subsystem**: Automated generation, ingestion, parsing, and continuous cataloging of software components in CycloneDX (v1.6/v1.7) and SPDX (v2.3/v3.0) formats.  
> 2. **Vulnerability Exploitability eXchange (VEX) Subsystem**: Bidirectional processing of machine-readable VEX statements (OpenVEX and CycloneDX VEX) to filter out non-exploitable vulnerabilities and communicate active product risk to downstream consumers.  
> 3. **Centralized Vulnerability Triage Ledger**: Stateful tracking of human audit decisions (such as *Accepted Risk*, *False Positive*, or *Mitigated*), complete with mandatory risk justifications, expiration dates, and automated integration with ROVER’s Pass/Fail Policy Rules Engine.

Aqua Security’s Trivy serves as the primary engine for this architecture. Trivy possesses native capabilities to generate CycloneDX and SPDX SBOMs during image and repository scans, scan pre-generated text-based SBOM manifests directly without re-analyzing raw container layers or cloning source repositories, and consume upstream VEX suppression documents via explicit execution flags.

## Data Modeling & Relational Schema Design

To transition ROVER from an ephemeral scan runner to a stateful software ledger, the PostgreSQL database must be expanded. In accordance with ROVER database schema standards, all categorical and status types use explicit VARCHAR definitions backed by Python StrEnum classes rather than native PostgreSQL ENUM types. This ensures transaction-safe schema migrations, multi-database test compatibility, and strict application-level validation. Non-sensitive provider configurations are stored in metadata_json text columns defaulting to empty JSON objects, while sensitive secrets remain strictly encapsulated within OpenBao Vault. All child tables enforce ON DELETE CASCADE constraints linked to parent products, releases, or assets.

### Database Schema Definitions

#### 1. Software Bill of Materials Table (sboms)

Stores raw generated or ingested SBOM document payloads bound directly to specific release assets.

| Column Name | Data Type | Constraints & Attributes | Description |
| :---- | :---- | :---- | :---- |
| id | UUID | PRIMARY KEY, DEFAULT gen_random_uuid() | Unique identifier for the SBOM record. |
| release_asset_id | UUID | NOT NULL, REFERENCES release_assets(id) ON DELETE CASCADE | Foreign key referencing the targeted release asset. |
| format | VARCHAR(50) | NOT NULL | Serialization standard (cyclonedx, spdx). |
| spec_version | VARCHAR(20) | NOT NULL | Specification version (e.g., 1.6, 2.3). |
| serial_number | VARCHAR(255) | NULLABLE | Unique URN serial number of the document. |
| raw_payload | TEXT | NOT NULL | Complete raw JSON payload of the SBOM document. |
| created_at | TIMESTAMPTZ | NOT NULL, DEFAULT CURRENT_TIMESTAMP | Initial ingestion timestamp. |

#### 2. Parsed Software Components Table (sbom_components)

Normalizes individual software libraries, binaries, and packages extracted from raw SBOM payloads to enable cross-product dependency querying.

| Column Name | Data Type | Constraints & Attributes | Description |
| :---- | :---- | :---- | :---- |
| id | UUID | PRIMARY KEY, DEFAULT gen_random_uuid() | Unique component record identifier. |
| sbom_id | UUID | NOT NULL, REFERENCES sboms(id) ON DELETE CASCADE | Foreign key link to the parent SBOM document. |
| name | VARCHAR(255) | NOT NULL | Component name (e.g., openssl, urllib3). |
| version | VARCHAR(100) | NOT NULL | Installed component version string. |
| purl | VARCHAR(1024) | NULLABLE | Standardized Package URL URN (RFC-compliant). |
| cpe | VARCHAR(255) | NULLABLE | Common Platform Enumeration string. |
| license_spdx | VARCHAR(100) | NULLABLE | Extracted SPDX license identifier (e.g., Apache-2.0). |
| component_type | VARCHAR(50) | NOT NULL | Component classification (library, container, operating-system). |

#### 3. Centralized Vulnerability Ledger Table (asset_vulnerabilities)

Aggregates and normalizes security findings discovered across all scanner plugins (Trivy, Semgrep, Snyk) into a unified operational ledger.

| Column Name | Data Type | Constraints & Attributes | Description |
| :---- | :---- | :---- | :---- |
| id | UUID | PRIMARY KEY, DEFAULT gen_random_uuid() | Unique vulnerability ledger identifier. |
| release_asset_id | UUID | NOT NULL, REFERENCES release_assets(id) ON DELETE CASCADE | Associated release asset reference. |
| scanner_name | VARCHAR(50) | NOT NULL | Originating engine (trivy, semgrep, snyk). |
| vulnerability_id | VARCHAR(100) | NOT NULL | Security advisory identifier (e.g., CVE-2024-1234, GHSA-xxx). |
| package_name | VARCHAR(255) | NOT NULL | Name of the affected library or OS package. |
| installed_version | VARCHAR(100) | NOT NULL | Installed package version detected at scan time. |
| fixed_version | VARCHAR(100) | NULLABLE | Vendor-provided fix version string. |
| severity | VARCHAR(20) | NOT NULL | Normalized severity (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN). |
| current_status | VARCHAR(50) | NOT NULL, DEFAULT 'open' | Lifecycle state (open, accepted_risk, false_positive, mitigated, resolved). |
| first_seen_at | TIMESTAMPTZ | NOT NULL, DEFAULT CURRENT_TIMESTAMP | Timestamp when finding was first recorded. |
| last_seen_at | TIMESTAMPTZ | NOT NULL, DEFAULT CURRENT_TIMESTAMP | Timestamp of most recent scan verification. |

#### 4. Vulnerability Triage Ledger Table (vulnerability_triage)

Persists human audit decisions, risk acceptances, and formal VEX justifications.

| Column Name | Data Type | Constraints & Attributes | Description |
| :---- | :---- | :---- | :---- |
| id | UUID | PRIMARY KEY, DEFAULT gen_random_uuid() | Unique triage decision identifier. |
| vulnerability_ledger_id | UUID | NOT NULL, REFERENCES asset_vulnerabilities(id) ON DELETE CASCADE | Target row in the centralized vulnerability ledger. |
| user_sub | VARCHAR(255) | NOT NULL, REFERENCES users(sub) | User subject identifier of the auditor. |
| status | VARCHAR(50) | NOT NULL | Assigned status (accepted_risk, false_positive, mitigated). |
| justification | VARCHAR(100) | NOT NULL | Standardized VEX justification string. |
| impact_statement | TEXT | NOT NULL | Mandatory human narrative explaining why vulnerability is unexploitable. |
| expires_at | TIMESTAMPTZ | NULLABLE | Expiration date for temporary risk acceptance. |
| created_at | TIMESTAMPTZ | NOT NULL, DEFAULT CURRENT_TIMESTAMP | Decision creation timestamp. |

#### 5. VEX Statements Repository Table (vex_statements)

Stores generated OpenVEX and CycloneDX VEX JSON documents derived from active triage decisions for API distribution and worker ingestion.

| Column Name | Data Type | Constraints & Attributes | Description |
| :---- | :---- | :---- | :---- |
| id | UUID | PRIMARY KEY, DEFAULT gen_random_uuid() | Unique VEX statement record identifier. |
| triage_id | UUID | NOT NULL, REFERENCES vulnerability_triage(id) ON DELETE CASCADE | Foreign key link to the originating triage entry. |
| spec_type | VARCHAR(50) | NOT NULL | Statement standard (openvex, cyclonedx_vex). |
| statement_json | TEXT | NOT NULL | Canonical JSON string of the exported VEX statement. |
| generated_at | TIMESTAMPTZ | NOT NULL, DEFAULT CURRENT_TIMESTAMP | Timestamp of statement generation. |

## Software Bill of Materials (SBOM) Subsystem Architecture

The SBOM subsystem provides two core capabilities: generating inventory documents during initial release analysis and continuously re-evaluating vulnerabilities using stored text-based SBOM manifests.

### Containerized SBOM Generation Mechanics

ROVER’s scan engine delegates execution to ephemeral container instances orchestrated by `rover.plugins.trivy`. To produce complete SBOM artifacts alongside standard vulnerability reports, the `TrivyScannerPlugin` executes Trivy using explicit output formatting flags tailored to the target asset type:

* **Container Image Assets**: For container targets, Trivy inspects the image filesystem layers, package database (such as dpkg, rpm, or apk), and language-specific dependency manifests. The worker invokes:  
  `trivy image --format cyclonedx --output /tmp/sbom.cdx.json --image-src docker <image_reference>`

* **Git Repository Assets**: For source code repositories cloned into ephemeral shared volumes, Trivy parses lockfiles and package manifests (including package-lock.json, poetry.lock, go.mod, and Cargo.lock). The worker invokes:  
  `trivy repo --format spdx-json --output /tmp/sbom.spdx.json /src`

Upon execution completion, `TrivyScannerPlugin` captures the generated JSON file, persists the raw payload into `sboms`, and parses its component nodes into discrete rows within `sbom_components`.

### The Zero-Docker Continuous SBOM Re-scanning Paradigm

Conventional security dashboards re-scan release packages by re-pulling large container images from remote registries or re-cloning Git repositories whenever vulnerability databases (such as NVD or GHSA) are updated. In enterprise environments managing hundreds of releases, this pattern incurs heavy network bandwidth costs, risks hitting registry rate limits, and consumes excessive host CPU cycles.  
ROVER bypasses these operational bottlenecks by implementing a continuous "Zero-Docker" re-scanning loop. Because an ingested CycloneDX or SPDX manifest contains a complete inventory of package names, versions, and Package URLs (PURLs), ROVER can re-evaluate an asset's vulnerability posture simply by scanning its cached text-based SBOM payload.  
The background worker process (`worker.py`) executes lightweight re-evaluations directly against cached SBOM files using Trivy’s `sbom` subcommand:

`trivy sbom /tmp/cached_sbom.cdx.json --format json --output /tmp/re-scan_results.json`

This operational pattern enables ROVER to execute hourly vulnerability re-evaluations across historical releases with minimal impact on system resources.

### Dual-Format Serialization & Export Strategy

ROVER natively supports both dominant open-source SBOM formats to satisfy distinct operational and regulatory requirements.

| Format Attribute | CycloneDX (v1.6 / v1.7) | SPDX (v2.3 / v3.0) |
| :---- | :---- | :---- |
| **Governing Body** | OWASP Foundation | Linux Foundation (ISO/IEC 5962:2021) |
| **Primary Use Case** | DevSecOps automation, active vulnerability analysis, and real-time risk tracking. | Legal compliance, open-source software licensing reviews, and procurement audits. |
| **VEX Native Support** | Direct native support via embedded vulnerabilities[] and affect schema blocks. | Handled via separate profile extensions or external annotations. |
| **Serialization Formats** | JSON, XML, Protocol Buffers | JSON, XML, RDF, Tag-Value |
| **ROVER Export API** | `GET /api/releases/{id}/sbom?format=cyclonedx` | `GET /api/releases/{id}/sbom?format=spdx` |

## Vulnerability Exploitability eXchange (VEX) & Triage Subsystem Architecture

Vulnerability scanners routinely flag security issues based purely on installed package version signatures. However, many flagged vulnerabilities are non-exploitable because the vulnerable code paths are never invoked, compensating network controls exist, or the vulnerable binary is excluded from the execution context. VEX provides a standardized, machine-readable mechanism to communicate the actual exploitability of flagged vulnerabilities, turning down scanner noise and focusing engineering effort on real security risks.

### Mapping Human Triage to International VEX Standards

When an auditor or product owner triages a vulnerability within the ROVER web interface, the application translates the selected disposition into standard VEX status codes and justification parameters.

| ROVER Triage Disposition | OpenVEX Status | CycloneDX VEX Status | Standard VEX Justification Code | Operational Criteria & Definition |
| :---- | :---- | :---- | :---- | :---- |
| **false_positive** | not_affected | not_affected | vulnerable_code_not_present | Scanner misidentified a package signature; the vulnerable source code is not present in the artifact. |
| **accepted_risk** | not_affected | not_affected | vulnerable_code_not_in_execute_path | Vulnerable library is installed but its vulnerable functions are unreachable during application execution. |
| **mitigated** | not_affected | not_affected | inline_mitigations_already_exist | Compensating controls (such as web application firewalls or read-only container filesystems) prevent exploitation. |
| **in_remediation** | under_investigation | under_investigation | *None (Justification omitted)* | The engineering team is actively investigating the finding; risk is unconfirmed. |
| **resolved** | fixed | fixed | *None (Justification omitted)* | A vendor patch or upgraded container image has been deployed to eliminate the vulnerability. |

### Bidirectional VEX Processing Architecture

ROVER operates a bidirectional VEX engine that handles both inbound VEX statements from upstream vendors and outbound VEX statements generated from internal triage actions.

#### 1. Inbound Ingestion (Vendor VEX & VEX Hub Processing)

Upstream software distributors (such as Red Hat, Canonical, or Alpine) publish VEX documents stating that certain vulnerabilities reported in their base images do not affect specific build configurations.  
During scan execution, `TrivyScannerPlugin` inspects the asset configuration for associated vendor VEX URLs or local VEX documents stored in `.vex/` repository directories. It passes these documents directly into Trivy using the `--vex` CLI flag:

`trivy image --vex /tmp/vendor_advisory.openvex.json --format json python:3.12-slim`

Vulnerabilities marked as `not_affected` within the vendor document are automatically suppressed during Trivy’s evaluation phase, preventing known non-issues from surfacing as active findings in ROVER reports.

#### 2. Outbound VEX Statement Generation & Export

When ROVER users triage findings, the system compiles all active `vulnerability_triage` records for a release into a canonical OpenVEX JSON document. This document is served publicly or via authenticated API endpoints (`/api/releases/{id}/vex.json`), allowing external security tools, CI/CD pipelines, or enterprise customers to ingest ROVER’s security assertions automatically.  
An exported OpenVEX document generated by ROVER follows this canonical structure:

```json
{  
  "@context": "https://openvex.dev/ns/v0.2.0",  
  "@id": "https://rover.local/api/vex/doc/550e8400-e29b-41d4-a716-446655440000",  
  "author": "ROVER Security Platform (human:admin@rover.local)",  
  "timestamp": "2026-07-28T12:00:00Z",  
  "version": 1,  
  "statements": [  
    {  
      "vulnerability": {  
        "name": "CVE-2024-21626"  
      },  
      "products": [  
        {  
          "@id": "pkg:docker/my-org/core-service@v1.4.0"  
        }  
      ],  
      "status": "not_affected",  
      "justification": "vulnerable_code_not_in_execute_path",  
      "impact_statement": "Container operates in unprivileged mode with a read-only root filesystem, rendering runc escape unreachable."  
    }  
  ]  
}
```

## End-to-End Operational Lifecycle & Policy Engine Alignment

The integration of Triage, VEX, and SBOM capabilities transforms ROVER's operational workflow into a closed-loop security posture pipeline.

```
                    +---------------------------------------+  
                    | 1. Ephemeral Multi-Scanner Evaluation |  
                    | (Trivy, Semgrep, Snyk Scan Execution)  |  
                    +---------------------------------------+  
                                        |  
                                        v  
                    +---------------------------------------+  
                    | 2. Central Ledger & SBOM Ingestion    |  
                    | (Populate `sboms` & `vulnerabilities`)|  
                    +---------------------------------------+  
                                        |  
                                        v  
                    +---------------------------------------+  
                    | 3. User Triage & VEX Generation       |  
                    | (Auditor Assigns Status & Expiration) |  
                    +---------------------------------------+  
                                        |  
                                        v  
                    +---------------------------------------+  
                    | 4. Policy Gate Compliance Evaluation   |  
                    | (Apply Pass/Fail Threshold Rules)     |  
                    +---------------------------------------+  
                                        |  
                                        v  
                    +---------------------------------------+  
                    | 5. Continuous Re-scan & Expiration    |  
                    | (`trivy sbom` & Expiration Worker)    |  
                    +---------------------------------------+
```

### Finding Lifecycle & State Machine

> 1. **Discovery & Ingestion**: Ephemeral scanners analyze target assets and insert newly discovered findings into `asset_vulnerabilities` with a status of `open`. Concurrently, generated SBOM payloads are stored in `sboms`.  
> 2. **Human Triage & Justification**: An auditor reviews the finding in the report UI and selects a disposition (e.g., *Accepted Risk*). The user provides a mandatory narrative impact statement and selects an optional expiration date.  
> 3. **VEX Generation**: ROVER creates a corresponding `vulnerability_triage` entry, updates the ledger status in `asset_vulnerabilities`, and renders a canonical OpenVEX JSON document stored in `vex_statements`.  
> 4. **Policy Gate Evaluation**: ROVER’s Pass/Fail Policy Rules Engine (Milestone 11) evaluates active findings against release security gates. Triaged findings with `not_affected` or `fixed` VEX statuses are excluded from policy failure calculations.  
> 5. **Asynchronous Monitoring & Re-scanning**: The background worker thread continuously re-evaluates cached SBOM manifests using `trivy sbom`. Concurrently, an expiration monitor revokes outdated risk acceptances.

### Automated Risk Acceptance Expiration Mechanics

Allowing unmonitored, permanent risk acceptances introduces long-term compliance exposure. ROVER addresses this by embedding automated expiration logic directly into its background worker engine.  
When a triage decision passes its configured expiration date (`expires_at <= CURRENT_TIMESTAMP`), a background maintenance task automatically invalidates the risk acceptance:

```sql
-- Automated Triage Expiration Cleanup executed by worker.py  
UPDATE asset_vulnerabilities  
SET current_status = 'open',  
    last_seen_at = CURRENT_TIMESTAMP  
WHERE id IN (  
    SELECT vulnerability_ledger_id  
    FROM vulnerability_triage  
    WHERE expires_at IS NOT NULL  
      AND expires_at <= CURRENT_TIMESTAMP  
      AND status IN ('accepted_risk', 'false_positive', 'mitigated')  
);
```

Once expired:

> 1. The finding’s lifecycle state in `asset_vulnerabilities` reverts from `accepted_risk` back to `open`.  
> 2. The associated VEX statement in `vex_statements` is flagged as superseded.  
> 3. Subsequent evaluations by the Pass/Fail Policy Rules Engine treat the finding as active, triggering compliance alerts and sending notifications across configured channels (Slack, Webhooks, Email).

## Implementation Strategy & Migration Roadmap

The implementation plan breaks down into four sequential phases to maintain platform stability and operational zero downtime.

### Phase 1: Database Layer Extensions (shipship Migrations)

Create migration script `migrations/0004_sbom_triage_vex.sql` to instantiate the five new database tables (`sboms`, `sbom_components`, `asset_vulnerabilities`, `vulnerability_triage`, `vex_statements`) along with foreign key indices. Implement corresponding database access modules under `src/rover/db/` (`sboms.py`, `triage.py`, `vex.py`) following established ORM and connection pooling patterns.

### Phase 2: Ephemeral Trivy Scanner Plugin Refactoring (rover.plugins.trivy)

Update the `TrivyScannerPlugin` module in `src/rover/plugins/trivy.py`:

* Modify execution commands to generate CycloneDX JSON artifacts alongside standard scan results.  
* Inject the `--vex` CLI flag dynamically when upstream vendor VEX documents are associated with the target asset.  
* Automatically parse and insert raw SBOM payloads into PostgreSQL upon scan completion.

### Phase 3: VEX Engine & Continuous Re-scanning Workers

Implement `src/rover/vex.py` to handle VEX document generation and parsing:

* Construct OpenVEX v0.2.0 and CycloneDX VEX JSON serializers to convert `vulnerability_triage` entries into valid VEX payloads.  
* Extend `worker.py` to include a background loop that re-evaluates cached SBOM manifests using `trivy sbom`.  
* Add the risk expiration cleanup routine to `worker.py` to continuously invalidate outdated risk acceptances.

### Phase 4: REST API & User Interface Controls

Extend Falcon route handlers in `src/rover/routes/` to expose dedicated HTTP endpoints:

| HTTP Method | API Endpoint Path | Description | Access Control |
| :---- | :---- | :---- | :---- |
| GET | /api/releases/{id}/sbom | Export consolidated SBOM document (format=cyclonedx\|spdx). | Bearer Token / Session |
| GET | /api/releases/{id}/vex.json | Export machine-readable OpenVEX document for a release. | Bearer Token / Session |
| POST | /api/vulnerabilities/{id}/triage | Submit human triage decision, updating ledger and VEX statements. | Product Owner / Admin |
| DELETE | /api/triage/{id} | Revoke an active triage disposition, reverting finding to open. | Product Owner / Admin |

Update web UI templates (`release_report.html`) to display inline triage controls, risk expiration date pickers, VEX status pills, and SBOM export menus.
