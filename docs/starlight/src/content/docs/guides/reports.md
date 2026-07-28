---
title: Vulnerability Reports & Deep-Linking
description: Explore multi-scanner vulnerability report views, tab deep-linking, and target cross-linking.
---

R.O.V.E.R. consolidates findings from Trivy, Semgrep, and Snyk into a single unified report interface.

---

## Direct Tab Navigation & Deep-Linking

When navigating to a release vulnerability report (`/reports/release/{release_id}` or `/reports/target`), use deep-linking URL parameters to share direct views with team members:
- `?tab=snyk`: Opens Snyk dependency & container findings tab directly.
- `?tab=semgrep`: Opens Semgrep SAST static analysis tab.
- `?tab=trivy`: Opens Trivy container vulnerability tab.

---

## Bidirectional Container-to-Repo Target Resolution

When a container image is manually linked to a source repository (or linked via CI metadata ingestion), the report view cross-resolves targets bidirectionally. Clicking **View Details** on any linked asset displays all 3 scanner tabs (Trivy image CVEs, Semgrep code security, and Snyk SCA findings) seamlessly in a single unified view.

---

## EOL Component Tracking

For software dependencies and base image components (e.g. Python 3.8, PostgreSQL 11, Ubuntu 18.04), R.O.V.E.R. checks cached End-Of-Life data from endoflife.date and displays lifecycle warnings alongside vulnerability reports.
