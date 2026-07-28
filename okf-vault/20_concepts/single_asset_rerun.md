---
id: "202607272318"
type: Concept
title: Single Asset Scanner Re-run (Planned Feature)
created: 2026-07-27
updated: 2026-07-27
tags:
  - feature
  - scanner
  - roadmap
status: draft
feature_status: planned
stale_after: 2027-07-27
---

# Single Asset Scanner Re-run

## Overview
Allows users to re-trigger a specific security scanner (Trivy, Semgrep, or Snyk) on an individual target asset within a Release without triggering full release re-scans across all assets.

## User Benefit
When an engineer fixes a vulnerability in a single repository or updates a single container image tag, they can re-evaluate that single asset immediately.

## Planned Implementation
- REST endpoint: `POST /api/assets/{id}/scans?scanner={trivy|semgrep|snyk}`
- UI: Individual **⚡ Scan** action button on scanner widgets in `product_release_detail.html`
- Docs: Update `docs/starlight/src/content/docs/guides/scanners.md` when deployed.
