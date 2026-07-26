---
id: "202607260851"
type: Index
title: ROVER Scanners Map of Content
description: Navigation index for ROVER vulnerability scanners and plugin specification notes.
created: "2026-07-26T08:51:00Z"
updated: "2026-07-26T08:51:00Z"
tags:
  - index/moc
  - rover/scanners
status: stable
aliases:
  - Scanners MOC
---

# ROVER Scanners Map of Content

> **Scope**: Navigation hub connecting scanner architecture specifications, active scanner plugins, and upstream reference resources.

## 1. Scanner Plugin Architecture & Security Policy
- [[rover-scanner-plugin-specification|ROVER Scanner Plugin Specification]]: Core protocol, data models (`ScanResult`), and plugin registry rules.
- [[container-image-digest-pinning|Container Image Digest Pinning Policy]]: Mandates explicit `sha256` digest pinning to protect against supply chain compromise.

## 2. Active Scanner Plugins
- [[trivy-scanner-plugin|Trivy Scanner Plugin]]: Container image & dependency CVE scanner.
- [[semgrep-scanner-plugin|Semgrep SAST Scanner Plugin]]: Static analysis source code security scanner.

## 3. External Tools & Security Advisories
- [[aquasec-trivy|Aqua Security Trivy]]: Vulnerability scanner tool reference.
- [[semgrep-sast|Semgrep SAST Engine]]: Static analysis engine reference.
- [[ghsa-69fq-xp46-6x23-trivy-supply-chain-advisory|GHSA-69fq-xp46-6x23 Advisory]]: Trivy supply chain security advisory.
