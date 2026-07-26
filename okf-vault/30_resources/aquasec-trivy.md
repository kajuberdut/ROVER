---
id: "202607260849"
type: Resource
title: Aqua Security Trivy
description: Comprehensive security scanner for container images, file systems, Git repositories, and cloud environments.
created: "2026-07-26T08:49:00Z"
updated: "2026-07-26T08:49:00Z"
tags:
  - resource/scanner
  - trivy
status: stable
stale_after: "2027-01-01"
aliases:
  - Trivy
---

# Aqua Security Trivy

> **Resource Metadata**:
> - **Source URL**: https://github.com/aquasecurity/trivy
> - **Publisher**: Aqua Security
> - **License**: Apache 2.0

## 1. Executive Summary
Trivy is an open-source vulnerability scanner designed for containers and cloud-native applications. It detects vulnerabilities in OS packages (apt, apk, yum) and language-specific dependencies (Python, Go, Node.js, Rust, etc.).

## 2. Integration in ROVER
ROVER executes Trivy inside ephemeral Docker containers (`aquasec/trivy:latest`) to scan both pre-built container images and cloned code repositories.

## 3. Connected Concepts
- [[trivy-scanner-plugin]]
- [[rover-scanner-plugin-specification]]
