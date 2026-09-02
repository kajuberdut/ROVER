---
title: User Roles & Product Permissions
description: Comprehensive guide to ROVER's system roles, product-level access control, email verification, and hybrid identity governance.
---

## Overview

R.O.V.E.R. implements a clean access control model:

1. **System Admin (`system_admin`)**: Global administrative privilege. System Admins have unrestricted access across system configuration, user management, notification destinations, and all products.
2. **Standard Viewer (`viewer`)**: Default role assigned to authenticated users on first login. Grants view access across all product dashboards, release assets, and scan reports.
3. **Email-Only User (`email_only`)**: Restricted role created solely for receiving notification alerts. Users with this role are restricted to managing their email subscription preferences at `/user/subscriptions` and cannot access product or scanner dashboards.
4. **Product-Level Roles**: Users can be assigned elevated roles (`write` or `admin`) on specific products to grant operational write capabilities or product administration rights.

---

## 1. Global System Roles

Global roles define server-wide application access:

### `system_admin`
- **Global Settings & Configuration**: Edit system configuration (`config.toml`), manage transport destinations, and configure server notification rules.
- **User Governance**: Provision users, create and revoke invitation links, assign global roles, and invalidate API tokens.
- **Universal Product Authority**: Implicit `admin` rights across every product in the system without requiring explicit product assignment.
- **Product Deletion**: Only a system admin may delete a product.

### `viewer` (Default)
- **Dashboard Access**: Access product dashboards, release packages, asset widgets, and multi-scanner reports.
- **Personal Notifications & API Tokens**: Manage personal notification subscriptions and issue personal API automation tokens.

### `email_only`
- **Passwordless Magic Links**: `email_only` users do not use passwords and are never added to Authelia's identity store. They access their subscription portal (`/user/subscriptions`) using 24-hour signed magic links emailed to their inbox or generated upon email confirmation.
- **Dashboard Shielding**: Attempts to access scanner dashboards, releases, or admin pages automatically redirect to `/user/subscriptions`.

### Identity Provider Group Synchronization
When a user logs in via OIDC, ROVER checks the user's group claims (`groups` or `roles`):
- If the user belongs to an admin group (e.g. `admins`, `system_admin`, `rover_admin`), ROVER sets `role = "system_admin"`.
- Otherwise, the user retains their assigned system role (`viewer` or `email_only`).

---

## 2. Product-Level Roles

For users who are not System Admins, product-level roles define granular permissions for specific products:

| Product Role | Description | Key Capabilities |
| :--- | :--- | :--- |
| **`view` (Default)** | Read-only access across the product | View product dashboard, releases, assets, scan schedules, and vulnerability reports. |
| **`write` (Limited Write)** | Operational write access | Add/edit repository and container assets, create releases, trigger manual scans, and edit Helm chart values. |
| **`admin` (Product Admin)** | Full administrative access to the product | Manage product scan schedules, edit product settings, and grant/modify product-level user roles for team members. |

---

## 3. Email Verification & Password Recovery

### Email Address Verification & Magic Links
- **Verification Links**: When an email destination or user account is created, ROVER generates a cryptographically signed verification link (`/confirm-email?token=...`) with a 24-hour expiration.
- **Instant Authentication**: Redeeming a verification link marks the email as verified (`is_verified = true`) and automatically sets a secure session cookie, taking the user directly to `/user/subscriptions`.
- **Magic Access Links**: Unauthenticated users can visit `/user/subscriptions` to request a passwordless magic access link sent directly to their email address.

### Password Reset Flow (Dashboard Users Only)
- **Request Link**: Dashboard users (`viewer` or `system_admin`) can visit `/forgot-password` to request a password reset link.
- **Reset Token**: Clicking the link routes to `/reset-password?token=...` with a 24-hour single-use token bound to the current password hash.
- **Credential Sync**: Submitting a new password updates Argon2id password hashes in Authelia's user registry (`users_database.yml`) for active dashboard accounts.

---

## 4. Hybrid Identity Governance & Token Revocation

### Web Sessions vs. Headless API Tokens
- **Web Sessions**: User identity and System Admin status are governed by your central Identity Provider. Deactivating a user in LDAP or Authelia blocks web login access immediately.
- **Headless API Tokens**: CI/CD automation tokens (`Authorization: Bearer <token>`) bypass web session authentication. To revoke headless access for a deactivated employee or service account, System Admins can use the **🔑 Revoke API Tokens** action under **Admin > User Management**.

---

## 5. Permission Summary Matrix

| Action / Endpoint | Email-Only (`email_only`) | Default View (`viewer`) | Product Write (`write`) | Product Admin (`admin`) | System Admin |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Access Self-Service Portal (`/user/subscriptions`) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Email Verification & Password Reset | ✅ | ✅ | ✅ | ✅ | ✅ |
| View Product, Releases, Assets & Reports | ❌ | ✅ | ✅ | ✅ | ✅ |
| Trigger Manual Scans & Add Assets | ❌ | ❌ | ✅ | ✅ | ✅ |
| Manage Product Scan Schedules | ❌ | ❌ | ❌ | ✅ | ✅ |
| Manage Product User Roles | ❌ | ❌ | ❌ | ✅ | ✅ |
| Global System Config & User Management | ❌ | ❌ | ❌ | ❌ | ✅ |
