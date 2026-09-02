---
id: "202608272145"
type: Concept
title: Email Verification, Password Reset & Unsubscribe Architecture
created: "2026-08-27T21:45:00Z"
updated: "2026-08-27T21:45:00Z"
tags:
  - concept/architecture
  - concept/notifications
  - concept/auth
  - rover/email
status: stable
stale_after: "2027-08-27"
aliases:
  - Email Verification Workflow
  - Password Reset Architecture
  - Self-Service Unsubscribe Portal
---

# Email Verification, Password Reset & Unsubscribe Architecture

> **Summary**: Specifies ROVER's email verification workflow, self-service password recovery integration with Authelia, and the self-service unsubscribe portal for standard and `email_only` users.

## 1. Overview
To ensure notification deliverability and provide account governance, ROVER decouples web authentication session scopes while enforcing email deliverability checks before dispatching active notifications.

---

## 2. Key Architecture Components

### 2.1 Email Verification Tokens (`itsdangerous` HMAC)
- **Token Generation**: Generates cryptographically signed tokens (`itsdangerous.URLSafeTimedSerializer`) using the application secret key and an `email-verification` salt with a 24-hour expiration window.
- **Verification Endpoint (`/confirm-email?token=...`)**:
  - Validates signature and timestamp.
  - Updates `users.is_verified = true` or `notification_destinations.is_verified = true`.
- **Dispatch Gate**: The notification engine (`dispatch_event`) checks `is_verified` status on SMTP and AWS SES destinations. Active notifications to unverified custom email destinations are logged as `skipped_unverified`.

### 2.2 Self-Service Password Reset & Authelia Integration
- **Recovery Request (`/forgot-password`)**: Generates a 24-hour single-use token (`password-reset` salt) bound to the user's current password hash (`ph`). Dispatches a recovery link via the default SMTP or AWS SES gateway.
- **Single-Use Enforcement**: When a password is updated, the user's `password_hash` in the database changes. Subsequent verification attempts comparing the embedded token hash (`token_ph`) against the user's current password hash (`current_ph`) fail immediately, permanently invalidating the redeemed token.
- **Password Reset (`/reset-password?token=...`)**: Validates recovery tokens, checks password length requirements (>= 8 characters), and rejects reused links.
- **Authelia Synchronization**: Updates Argon2id password hashes directly in Authelia's `users_database.yml` file under an exclusive file lock (`fcntl.flock`), triggers an Authelia container restart, and updates local database records.

### 2.3 `email_only` Role & Passwordless Magic Access Portal (`/user/subscriptions`)
- **Passwordless Security Model**: `email_only` users do NOT possess passwords and are NEVER provisioned in Authelia's OIDC directory (`users_database.yml`), eliminating credential attack surface.
- **Magic Access Tokens**: Users access `/user/subscriptions` using 24-hour signed tokens (`magic-access-token` salt) emailed upon request or embedded in email confirmation links.
- **Session Cookie Issuance**: Redeeming a valid magic access token automatically sets a secure session cookie (`rover_session`), granting immediate access to manage rules or unsubscribe.
- **Middleware Guard**: Falcon ASGI middleware (`RequireAuthMiddleware`) restricts `email_only` users strictly to `/user/subscriptions`, `/confirm-email`, and `/logout`. Any attempt to navigate to product or scanner dashboards is redirected to `/user/subscriptions`.
- **Subscription Management**:
  - Displays user email verification status with a **Resend Verification Link** action.
  - Lists all active notification subscription rules tied to the user account.
  - Provides single-rule **Unsubscribe** actions and an **Unsubscribe All** bulk removal handler.

---

## 3. Relationships & Context
- **Parent Index**: [[roadmap-moc]]
- **Related Concepts**:
  - [[notification_system_architecture]]
  - [[hybrid-identity-rbac-architecture]]
  - [[user-roles-and-product-permissions]]
  - [[m6-notifications]]
