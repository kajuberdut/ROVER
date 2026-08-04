---
id: "202608030819"
type: Concept
title: User Roles & Product Permissions Architecture
created: "2026-08-03T08:19:00Z"
updated: "2026-08-03T08:19:00Z"
tags:
  - concept/architecture
  - concept/permissions
  - rover/rbac
status: stable
stale_after: "2027-08-03"
aliases:
  - System Admin and Product Roles
  - ROVER Role-Based Access Control
---

# User Roles & Product Permissions Architecture

> **Summary**: Documents ROVER's simplified access control model: System Admin as a global boolean privilege, default read access (`view`) across all products for all authenticated users, and optional product-level `write` or `admin` role assignments.

## 1. Overview
ROVER decouples global administrative privileges from product-level operational roles:
- **System Admin (`system_admin` Boolean)**: Managed dynamically via Identity Provider (Authelia / LDAP) group membership. Grants full system management (settings, users, invitations, API token revocation) and implicit administrative rights over all products.
- **Default View Access (`view`)**: All authenticated users have read-only access to all products, releases, assets, scan schedules, and vulnerability reports by default.
- **Product-Level Elevated Roles**: Users can be assigned `write` or `admin` roles on specific products to grant operational or administrative capabilities.

## 2. Product-Level Roles
- **`view` (Default)**: View dashboard cards, release evaluations, asset inventories, schedules, and reports.
- **`write` (Product Write)**: Add/remove repository and container assets, manage releases, trigger manual scans, and edit Helm chart values.
- **`admin` (Product Admin)**: Manage product scan schedules, edit product settings, and manage product user assignments.

## 3. Relationships & Context
- **Parent Index**: [[roadmap-moc]]
- **Related Concepts**:
  - [[hybrid-identity-rbac-architecture]]
  - [[lldap-identity-backend]]
  - [[m17-audit-log]]
