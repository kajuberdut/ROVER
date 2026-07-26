---
id: "202607261114"
type: Resource
title: GitHub Security Advisory GHSA-69fq-xp46-6x23 (Trivy Ecosystem)
description: Security advisory detailing supply chain risks in Trivy ecosystem image tagging.
created: "2026-07-26T11:14:00Z"
updated: "2026-07-26T11:14:00Z"
tags:
  - resource/security-advisory
  - supply-chain
  - trivy
status: stable
stale_after: "2027-01-01"
aliases:
  - GHSA-69fq-xp46-6x23
---

# GitHub Security Advisory GHSA-69fq-xp46-6x23

> **Resource Metadata**:
> - **Source URL**: https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23
> - **Publisher**: Aqua Security / GitHub Advisory Database
> - **CVE / Advisory ID**: GHSA-69fq-xp46-6x23

## 1. Executive Summary
Security advisory GHSA-69fq-xp46-6x23 highlights supply chain risks associated with un-pinned container image tags within the Trivy ecosystem. Mutable container tags permit potential tampering or unauthorized image replacement if upstream container registries or tag pointers are manipulated.

## 2. Mitigation Strategy
To prevent exposure to compromised image tags, security tooling MUST enforce strict `sha256` digest pinning for all scanner container images.

## 3. Connected Concepts
- [[container-image-digest-pinning|Container Image Digest Pinning Policy]]
- [[trivy-scanner-plugin]]
- [[aquasec-trivy]]
