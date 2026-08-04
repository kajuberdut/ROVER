---
title: User Roles & Product Permissions
description: Comprehensive guide to ROVER's system roles, product-level access control, and hybrid identity governance.
---

## Overview

R.O.V.E.R. implements a clean, intuitive access control model:

1. **System Admin (`System Admin`)**: A global boolean administrative privilege. System Admins have unrestricted access across system configuration, user management, and all products.
2. **Default View Access**: All authenticated users are granted **View (`view`)** access by default across all products, releases, assets, and vulnerability reports.
3. **Product-Level Roles**: Users can be assigned elevated roles on specific products to grant write capabilities or product administration rights.

---

## 1. System Administration (`System Admin`)

`System Admin` is a global boolean flag assigned to a user account. It is managed centrally through your Identity Provider (Authelia, JumpCloud, or LDAP).

### System Admin Capabilities
- **Global Settings & Configuration**: Edit system configuration (`config.toml`), manage email destinations, and configure notification rules.
- **User Governance**: Create and revoke invitation links, view all system users, and invalidate API tokens.
- **Universal Product Authority**: Implicit `Product Admin` rights across every product in the system without requiring explicit product assignment.
- **Product Deletion**: Only a system admin may delete a product.

### Identity Provider Group Synchronization
When a user logs in via OIDC, ROVER checks the user's group claims (`groups` or `roles`):
- If the user belongs to an admin group (e.g. `admins`, `system_admin`, `rover_admin`), ROVER sets `system_admin = true`.
- Otherwise, `system_admin = false`.

---

## 2. Product-Level Roles

For users who are not System Admins, product-level roles define granular permissions for specific products:

| Product Role | Description | Key Capabilities |
| :--- | :--- | :--- |
| **`view` (Default)** | Read-only access across the product | View product dashboard, releases, assets, scan schedules, and vulnerability reports. |
| **`write` (Limited Write)** | Operational write access | Add/edit repository and container assets, create releases, trigger manual scans, and edit Helm chart values. |
| **`admin` (Product Admin)** | Full administrative access to the product | Manage product scan schedules, edit product settings, and grant/modify product-level user roles for team members. |

---

## 3. Hybrid Identity Governance & Token Revocation

### Web Sessions vs. Headless API Tokens
- **Web Sessions**: User identity and System Admin status are governed by your central Identity Provider. Deactivating a user in LDAP or Authelia blocks web login access immediately.
- **Headless API Tokens**: CI/CD automation tokens (`X-API-Token`) bypass web session authentication. To revoke headless access for a deactivated employee or service account, System Admins can use the **🔑 Revoke API Tokens** action under **Admin > User Management**.

---

## 4. Permission Summary Matrix

| Action / Endpoint | Default View (`view`) | Product Write (`write`) | Product Admin (`admin`) | System Admin |
| :--- | :---: | :---: | :---: | :---: |
| View Product, Releases, Assets & Reports | ✅ | ✅ | ✅ | ✅ |
| Trigger Manual Scans & Add Assets | ❌ | ✅ | ✅ | ✅ |
| Manage Product Scan Schedules | ❌ | ❌ | ✅ | ✅ |
| Manage Product User Roles | ❌ | ❌ | ✅ | ✅ |
| Global System Config & User Management | ❌ | ❌ | ❌ | ✅ |
