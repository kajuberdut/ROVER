---
id: "202607260850"
type: Resource
title: Semgrep SAST Engine
description: Fast, open-source static analysis engine for searching code, enforcing code standards, and finding security bugs.
created: "2026-07-26T08:50:00Z"
updated: "2026-07-26T08:50:00Z"
tags:
  - resource/scanner
  - semgrep
status: stable
stale_after: "2027-01-01"
aliases:
  - Semgrep
---

# Semgrep SAST Engine

> **Resource Metadata**:
> - **Source URL**: https://github.com/semgrep/semgrep
> - **Publisher**: Semgrep, Inc.
> - **License**: LGPL 2.1

## 1. Executive Summary
Semgrep is a lightweight static analysis tool for querying codebases using pattern-matching rules. It analyzes abstract syntax trees (AST) to identify security flaws, secret leaks, and logic errors.

## 2. Integration in ROVER
ROVER utilizes Semgrep for static application security testing (SAST) of Git repository assets, mounting repository clones into ephemeral `semgrep/semgrep` containers.

## 3. Connected Concepts
- [[semgrep-scanner-plugin]]
- [[rover-scanner-plugin-specification]]
