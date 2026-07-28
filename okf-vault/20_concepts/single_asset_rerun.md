---
id: "202607272318"
type: Concept
title: Single Asset Scanner Re-run
created: 2026-07-27
updated: 2026-07-28
tags:
  - feature
  - scanner
  - roadmap
status: stable
feature_status: completed
stale_after: 2027-07-27
---

# Single Asset Scanner Re-run

## Overview
Allows users to re-trigger a specific security scanner (Trivy, Semgrep, or Snyk) on an individual target asset within a Release without triggering full release re-scans across all assets.

## User Benefit
When an engineer fixes a vulnerability in a single repository or updates a single container image tag, they can re-evaluate that single asset immediately.

## Implementation Details
- REST endpoint: `POST /api/assets/{release_asset_id}/scans?scanner={trivy|semgrep|snyk|all}`
- UI: Individual **⚡ Scan** action buttons on scanner widgets and action column in `release_assets_table.html`
- Docs: Updated `docs/starlight/src/content/docs/guides/scanners.md`.
