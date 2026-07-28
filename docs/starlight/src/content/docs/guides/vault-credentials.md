---
title: OpenBao Credential Vault
description: Manage API tokens and private container registry credentials securely.
---

R.O.V.E.R. integrates with **OpenBao Vault** to manage sensitive credentials securely without storing secrets in plaintext database tables or source code repositories.

---

## Supported Credential Types

- **API Tokens**: Snyk API tokens, Semgrep Pro API tokens, and external scanner integration keys.
- **Container Registry Credentials**: Docker Hub, GitHub Container Registry (GHCR), Amazon ECR, and private registry username/password credentials.

---

## Managing Vault Credentials

1. System Admins can access **🔒 Credential Vault** from the top-right user menu (`/admin/credentials`).
2. Click **+ Add Credential**.
3. Select credential type, name, and secret values.
4. Credentials are automatically encrypted inside OpenBao (`secret/data/rover/*`) and referenced by UUID in R.O.V.E.R. configuration forms.

---

## Secure Worker Injection

During scanner job execution, worker processes fetch credentials directly from OpenBao over encrypted TLS connections, inject them into ephemeral container process environments, and purge secrets from memory immediately upon job completion.
