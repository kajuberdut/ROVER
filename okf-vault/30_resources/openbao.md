---
id: "202607261122"
type: Resource
title: OpenBao Secrets Engine
description: Open-source, community-governed security tool for managing secrets and sensitive data.
created: "2026-07-26T11:22:00Z"
updated: "2026-07-26T11:22:00Z"
tags:
  - resource/security
  - openbao
status: stable
stale_after: "2027-01-01"
aliases:
  - OpenBao
---

# OpenBao Secrets Engine

> **Resource Metadata**:
> - **Source URL**: https://openbao.org / https://github.com/openbao/openbao
> - **Publisher**: Linux Foundation / OpenBao Community
> - **License**: MPL 2.0 (Mozilla Public License)

## 1. Executive Summary
OpenBao is an open-source fork of HashiCorp Vault created to preserve a open-source, community-governed secrets engine. It maintains drop-in REST API compatibility with Vault.

## 2. Integration in ROVER
ROVER runs OpenBao in Docker Compose alongside an auto-unseal sidecar container (`openbao-unseal`), providing dynamic secret storage for Git tokens, registry auth, and API keys retrieved via the `hvac` Python library.

## 3. Connected Concepts
- [[openbao-secret-injection|OpenBao Dynamic Secret Injection]]
- [[m1-credential-management|M1 · Credential Management]]
