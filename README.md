# R.O.V.E.R

**R**elease **O**riented **V**ulnerability **E**valuation & **R**eporting

A lightweight, Falcon-backed security dashboard for aggregating and reporting multi-repository vulnerability scans across release tags.

## Getting Started

ROVER is Docker-first. All services (the web application, Authelia identity provider, and Nginx reverse proxy) are orchestrated with Docker Compose. The Docker daemon is a hard dependency — it is used both to run the stack and to execute ephemeral Trivy vulnerability scan containers.

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) with Compose plugin
- `openssl` (for generating local TLS certificates)

### First-Time Setup

#### 1. Clone the repository

```bash
git clone <repo-url> && cd ROVER
```

#### 2. Run the setup script

`setup.sh` generates all secrets and TLS certificates from the committed `*.example` templates. It is safe to re-run and will never overwrite existing files.

```bash
chmod +x setup.sh && ./setup.sh
```

The script will:
- Generate a self-signed wildcard TLS certificate for `*.rover.local` (Nginx requires HTTPS for Authelia's Secure cookies)
- Generate random secrets for Authelia (`jwt_secret`, `session_secret`, `encryption_key`, `hmac_secret`)
- Generate a fresh RSA private key for the OIDC JSON Web Key Set
- Prompt you for an admin password and hash it with Argon2
- Write the completed `authelia/configuration.yml` and `authelia/users_database.yml` from the `.example` templates
- Print a `/etc/hosts` reminder if the local domains aren't mapped yet

#### 3. Add host entries (first time only)

```
127.0.0.1 rover.local auth.rover.local
```

#### 4. Start the stack

```bash
docker compose up --build -d
```

Navigate to **https://rover.local**. Accept the self-signed certificate warning on first visit.

> **Note:** Because the certificate is self-signed, your browser will show a privacy warning. Click **Advanced → Proceed** to continue. In a production environment, replace these with certificates from Let's Encrypt or your organisation's CA.

---

### User Roles

ROVER uses role-based access control layered on top of Authelia authentication. Roles are managed by admins via the `/admin/users` page.

| Capability | Viewer | Product Owner | Admin |
|---|:---:|:---:|:---:|
| View dashboards & reports | ✅ | ✅ | ✅ |
| Trigger scans | ✅ | ✅ | ✅ |
| Create products | ❌ | ✅ (becomes owner) | ✅ |
| Modify owned products & releases | ❌ | ✅ | ✅ |
| Modify any product or release | ❌ | ❌ | ✅ |
| Add / remove release assets | ❌ | ✅ (owned) | ✅ |
| Toggle EOL status | ❌ | ✅ (owned) | ✅ |
| Manage user roles | ❌ | ❌ | ✅ |

New users are assigned the `viewer` role by default on first login.

---

### Architecture

- **App Setup**: Falcon ASGI application instance with `RequireAuthMiddleware` that enforces OIDC session cookies on all routes.
- **Authentication**: [Authelia](https://www.authelia.com/) acts as the OpenID Connect identity provider. ROVER acts as a Relying Party using [Authlib](https://authlib.org/) for JWT validation and [itsdangerous](https://itsdangerous.palletsprojects.com/) for signed local session cookies.
- **Reverse Proxy**: Nginx terminates TLS and routes `rover.local` → Falcon and `auth.rover.local` → Authelia.
- **Routing**: Resource classes mapped to routes for the main dashboard and specific report views.
- **Templating**: Jinja2 environment to load HTML templates from a local directory, complete with deep JSON parsing for vulnerability datasets.
- **Styling**: Includes PicoCSS from `./static/css` in the base HTML template `<head>` for clean, minimal styling.
- **Frontend Interactivity**: Lightweight, dependency-free Vanilla JavaScript is used to handle dynamic UX features like:
  - Background auto-polling of the queue table using the `fetch` API.
  - Floating combo-button navigation on long reports managed via `IntersectionObserver`.
  - Dynamic remote repository and container image tag querying (`git ls-remote`, `skopeo list-tags`) coupled to a custom PicoCSS segmented button UI.
  - Inline entity mapping workflows with auto-expanding contextual layouts.
- **Job Queue**: A lightweight `sqlite3` queue (`scan_queue.py`) manages asynchronous scanning jobs without needing heavy external message brokers.
- **Worker Thread**: `worker.py` runs an `asyncio` loop inside a background Python thread alongside Falcon, gracefully picking up jobs from SQLite.
- **Artifact Bundles**: Users can logically group and track multiple Git Repositories and Docker Images together under Release Packages, rolling up all vulnerability metrics into a unified dashboard view.
- **Scanner Execution**: The `scanner.py` utility utilizes `testcontainers` to launch ephemeral, isolated `aquasec/trivy:latest` Docker containers. This ensures no host-system dependencies are needed beyond Docker itself.
  - **Caching**: The application uses a Docker named volume (`trivy-vulnerability-db-cache`) injected securely during scan runtime, caching the heavy 40-200MB vulnerability DB.
