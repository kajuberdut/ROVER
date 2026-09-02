---
id: "202607312226"
type: Concept
title: LLDAP Identity Backend Architecture
created: "2026-07-31T22:26:00Z"
updated: "2026-07-31T22:26:00Z"
tags:
  - concept/architecture
  - concept/identity
  - rover/auth
status: draft
stale_after: "2027-07-31"
aliases:
  - LLDAP Integration
  - Lightweight LDAP Identity Provider
---

# LLDAP Identity Backend Architecture

> **Summary**: Long-term architectural proposal to replace Authelia's local file-based user database (`users_database.yml`) with LLDAP (Lightweight LDAP) for enterprise identity management and REST API user provisioning.

## 1. Overview
Currently, ROVER uses Authelia with a file-backed authentication store (`authelia/users_database.yml`). User registration and invitation redemption modify this file directly with file locking (`fcntl.flock`). 

While this file-backed design is lightweight and self-contained for single-node deployments, enterprise multi-node deployments benefit from a dedicated identity provider. LLDAP is a modern, lightweight LDAP server (~20MB RAM footprint) featuring an integrated Web UI, built-in SQLite/PostgreSQL storage, and a GraphQL/REST API for user administration.

## 2. Key Mechanisms & Components

### 2.1 Proposed Service Architecture
- **LLDAP Container Service**: Added to `docker-compose.yml` (`image: lldap/lldap:latest`).
- **Authelia LDAP Backend**: Authelia configured with `authentication_backend.ldap` pointing to `ldap://lldap:389`.
- **API-Driven Provisioning**: ROVER's backend uses LLDAP's REST/GraphQL API to programmatically create, update, and disable user accounts upon invitation acceptance, eliminating direct file writes to `users_database.yml`.

### 2.2 Benefits Over File Backend
1. **Decoupled Security Bounds**: ROVER containers no longer require volume mounts to raw password database files.
2. **REST API User Management**: Eliminates YAML parsing and file locking code in Python.
3. **Centralized Directory Sync**: Standard LDAP protocol support enables external identity synchronization and centralized authentication.

## 3. Implementation Plan (Long-Term / Backlog)
1. Add `lldap` service to Docker Compose stack.
2. Update `authelia/configuration.yml` template to support `authentication_backend.ldap`.
3. Build an LLDAP API client service in `src/rover/auth.py`.
4. Update `bin/setup.sh` provisioning routines to initialize LLDAP admin credentials.

## 4. Relationships & Context
- **Parent Index**: [[roadmap-moc]]
- **Related Concepts**:
  - [[m1-credential-management]]
