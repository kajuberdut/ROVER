---
id: "202608010915"
type: Concept
title: Hybrid Identity & Access Governance Architecture
created: "2026-08-01T09:15:00Z"
updated: "2026-08-01T09:15:00Z"
tags:
  - concept/architecture
  - concept/identity
  - rover/auth
status: stable
stale_after: "2027-08-01"
aliases:
  - Hybrid Identity Model
  - IdP Group Role Sync & Revocation
---

# Hybrid Identity & Access Governance Architecture

> **Summary**: Specifies ROVER's hybrid identity model where primary authentication and System Admin vs. Viewer role determination are governed by the Identity Provider (Authelia / LDAP / JumpCloud), while fine-grained domain permissions, product ownership, and CI/CD API tokens are managed in ROVER.

## 1. Overview
In enterprise security deployments, access governance requires a clear boundary between **Identity & System Privilege Management** (handled by the central Identity Provider / Directory Service) and **Application Domain Governance** (handled locally inside ROVER).

ROVER implements a **Hybrid Identity Architecture**:
- **Identity Provider (Authelia / LDAP / JumpCloud)**: Owns user directory, password policies, multi-factor authentication, account activation/deactivation, and global System Admin vs. Viewer role assignments via group claims.
- **ROVER Application**: Owns product-level access control, asset scoping, scheduled scan definitions, notification rules, and headless CI/CD pipeline API tokens.

## 2. Key Mechanisms

### 2.1 System Role Synchronization from IdP Groups
On every successful OIDC authentication callback (`/callback`), ROVER inspects the `groups` or `roles` claim in the OIDC ID Token or UserInfo response:
- **Admin Group Detection**: If `groups` contains `admins`, `admin`, `system_admin`, or `rover_admin`, ROVER automatically sets `users.role = "system_admin"`.
- **Standard User Default**: If `groups` does not contain an admin group, ROVER sets `users.role = "viewer"`.
- **Dynamic Role Updates**: Promoting or revoking admin status in the IdP (e.g. JumpCloud LDAP) takes effect in ROVER immediately upon the user's next login.

### 2.2 Account Deactivation & Access Revocation
When a user is disabled or removed in the central directory (e.g. JumpCloud / LDAP):
1. **Web Authentication Revocation**: Authelia/LDAP immediately rejects OIDC login attempts. The user can no longer establish a web session.
2. **Headless API Token Invalidation**: Because CI/CD pipeline automation relies on static API tokens (`X-API-Token`) that bypass OIDC, ROVER provides System Admins with an explicit **"Revoke API Tokens"** action in `/admin/users` to immediately terminate all active tokens for a deactivated user.

## 3. Relationships & Context
- **Parent Index**: [[roadmap-moc]]
- **Related Concepts**:
  - [[lldap-identity-backend]]
  - [[ephemeral-authelia-provisioner]]
  - [[m1-credential-management]]
