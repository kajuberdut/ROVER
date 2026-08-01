---
id: "202607312228"
type: Concept
title: Ephemeral Cryptographic Handoff Authelia Provisioner
created: "2026-07-31T22:28:00Z"
updated: "2026-07-31T22:28:00Z"
tags:
  - concept/architecture
  - concept/security
  - rover/auth
status: draft
stale_after: "2027-07-31"
aliases:
  - Ephemeral Authelia Provisioner
  - Cryptographic Handoff Provisioning Pattern
---

# Ephemeral Cryptographic Handoff Authelia Provisioner

> **Summary**: Near-term security architecture that replaces direct `users_database.yml` write access in the main `web` service with signed payload tokens and short-lived, network-isolated ephemeral containers (`--network none`).

## 1. Overview
In a containerized environment, principle of least privilege dictates that the primary web application container should not hold write access to user credentials or identity provider configuration files.

Rather than running a heavy, always-on sidecar daemon, ROVER can leverage an **Ephemeral Cryptographic Handoff Pattern**. When a user registers or redeems an invitation, the main `web` container generates a cryptographically signed payload token (HMAC-SHA256 / JWT) containing user details, drops it into a staging volume, and spawns a single-use container to perform the YAML update.

```
┌─────────────────────────┐          1. Sign & write payload JWT          ┌─────────────────────────┐
│     ROVER Web App       │──────────────────────────────────────────────>│   /tmp/rover-tokens/    │
│  (users_database.yml:ro)│                                               │   <token_id>.jwt        │
└─────────────────────────┘                                               └─────────────────────────┘
            │                                                                          ▲
            │ 2. Spawns `docker run --rm --network none`                               │ Read & Verify
            ▼                                                                          │ Token
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                      Ephemeral Provisioner Container (0.3 sec lifecycle)               │
│  - Network: Isolated (`--network none`)                                                │
│  - Mounts: `/tokens:ro`, `users_database.yml:rw`                                       │
│  - Action: Verifies signature, updates YAML with file lock, cleans up token, exits    │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

## 2. Key Mechanics & Security Controls

### 2.1 Read-Only Main Service Mount
The main `web` container mounts `authelia/users_database.yml` in **Read-Only (`:ro`)** mode. If the web container is compromised via RCE or path traversal, an attacker cannot modify or overwrite the user database or elevate privileges.

### 2.2 Complete Network Isolation (`--network none`)
The ephemeral provisioner container is launched with `--network none`. It has no network interface, ensuring zero external data exfiltration capability during its 300ms execution window.

### 2.3 Cryptographic Token Verification
The provisioner verifies the payload's HMAC-SHA256 signature against the shared secret (`ROVER_SECRET_KEY`) before modifying `users_database.yml`. Tampered or unsigned payload files are immediately rejected.

### 2.4 Zero Idle Resource Overhead
Because the container is executed on-demand via Docker socket (`docker run --rm`) and exits immediately after completing the write, idle CPU and RAM usage is 0 MB.

## 3. Workflow Steps
1. **Token Generation**: `web` service creates payload `{ username, password_hash, email, display_name, expires_at }` and signs it using `ROVER_SECRET_KEY`.
2. **File Staging**: Payload written to `/tmp/rover-tokens/<token_id>.jwt`.
3. **Execution**: `web` runs `docker run --rm --network none -v /tmp/rover-tokens:/tokens:ro -v ../authelia/users_database.yml:/users_database.yml:rw ...`.
4. **Processing**: Provisioner verifies signature, acquires file lock (`fcntl.flock`), appends user entry, deletes the token file, and exits with code 0.
5. **Response**: `web` confirms completion and returns HTTP response to user.

## 4. Relationships & Context
- **Parent Index**: [[roadmap-moc]]
- **Related Concepts**:
  - [[lldap-identity-backend]]
  - [[m1-credential-management]]
