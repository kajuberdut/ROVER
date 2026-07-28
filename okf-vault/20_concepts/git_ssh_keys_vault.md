---
id: "202607272321"
type: Concept
title: Git SSH Deploy Keys in OpenBao Vault (Planned Feature)
created: 2026-07-27
updated: 2026-07-27
tags:
  - feature
  - vault
  - ssh
  - roadmap
status: draft
feature_status: planned
stale_after: 2027-07-27
---

# Git SSH Deploy Keys in OpenBao Vault

## Overview
Planned feature to store private SSH deploy keys securely in OpenBao Vault (`secret/data/rover/credentials/*`) and inject them via ephemeral `GIT_SSH_COMMAND` settings during private repository scans.

## Planned Implementation
- Schema support for RSA/Ed25519 private keys in OpenBao Vault engine
- UI credential type selector in `/admin/credentials`
- Ephemeral SSH agent / environment file injection in `src/rover/scanner/` worker
- User guide updates in `docs/starlight/src/content/docs/guides/vault-credentials.md`
