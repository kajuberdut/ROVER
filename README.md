# R.O.V.E.R

**R**elease **O**riented **V**ulnerability **E**valuation & **R**eporting

A lightweight, Falcon-backed security dashboard for aggregating and reporting multi-repository vulnerability scans across release tags.

Planned features are tracked in [ROADMAP.md](ROADMAP.md).

![ROVER Import Helm Feature](docs/images/readme/01-import-helm.png)

## Getting Started

ROVER is Docker-first. All services (the web application, PostgreSQL database, Authelia identity provider, and Nginx reverse proxy) are orchestrated with Docker Compose. The Docker daemon is a hard dependency — it is used both to run the stack and to execute ephemeral Trivy vulnerability scan containers.

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

## Should I Use ROVER?

ROVER is a good fit if your team self-hosts tooling, tracks multiple products and releases, and wants a single place to own vulnerability data without per-seat licensing costs.

It may not be the right fit if you need a managed service, an SLA, or features like runtime threat detection and cloud posture management.

See [VALUE.md](VALUE.md) for a full breakdown of strengths, tradeoffs, and a comparison table against commercial alternatives.

---

## Disclaimer of Affiliation and Third-Party Trademarks

Trivy, Semgrep, and Snyk are trademarks of their respective owners. Any reference to these tools within the R.O.V.E.R project or by Kajuberdut is strictly for informational and compatibility purposes. 

No association, sponsorship, endorsement, or affiliation exists between R.O.V.E.R (or Kajuberdut) and the owners of these trademarks. The use of these names does not imply any binding agreement or official relationship. 

Users of R.O.V.E.R are solely responsible for reviewing and complying with the respective licenses, terms of service, and usage policies of Trivy, Semgrep, Snyk, and any other third-party software referenced or utilized by this project.

---

### Source Code Discovery & OCI Annotations

When dealing with pre-built container images (e.g., those imported from a Helm Chart), ROVER natively relies on **OCI Image Annotations** to dynamically discover the underlying Git repository for SAST scanning via Semgrep.

Because compiled container images often do not contain raw source code (like Go or Rust application binaries), Semgrep cannot naturally inspect them. To bridge this gap, modern CI/CD builders (like GitHub Actions and BuildKit) use standard annotations—most notably `org.opencontainers.image.source`—to explicitly bake the originating Git repository URL into the image metadata.

By relying on these industry-standard OCI annotations, ROVER can automatically correlate an opaque container image back to its source repository and continuously audit the underlying codebase without requiring manual user mapping.
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
- **Job Queue**: A PostgreSQL-backed queue (`scan_queue.py`) manages asynchronous scanning jobs without needing heavy external message brokers like RabbitMQ or Redis. Two queues are maintained: `scan_jobs` (Trivy) and `semgrep_jobs` (Semgrep).
- **Worker Thread**: `worker.py` runs an `asyncio` loop inside a background Python thread alongside Falcon, gracefully picking up jobs from both PostgreSQL queues each iteration.
- **Artifact Bundles**: Users can logically group and track multiple Git Repositories and Docker Images together under Release Packages, rolling up all vulnerability metrics into a unified dashboard view.
- **Scanner Execution**: The `scanner.py` utility utilizes `testcontainers` to launch ephemeral, isolated Docker containers for scanning.
  - **Trivy (CVE)**: Runs `aquasec/trivy:latest` for dependency and container image vulnerability scanning. Uses a named Docker volume (`trivy-vulnerability-db-cache`) to cache the vulnerability database between scans.
  - **Semgrep (SAST)**: Runs `semgrep/semgrep` for static analysis of repository source code (repo assets only). The repository is cloned into an ephemeral named Docker volume via an `alpine/git` container so it is accessible to the sibling Semgrep container launched from the host daemon. The volume is removed after each scan.
  - **Semgrep Caching**: Semgrep scans are cached by full SHA-1 commit hash. If a completed scan already exists for a given commit, the worker reuses those results without re-running the container — so scheduled re-scans only run Trivy (whose vulnerability DB changes over time) while Semgrep re-runs only when new commits are introduced.
- **Report Page**: Scan reports display Trivy CVE results in a fixed-layout table. When a Semgrep job also exists for a repo scan, a tab bar appears alongside showing finding counts. The active tab is persisted in the URL hash for bookmarking and page-refresh stability.

---

## Credits & Origins

ROVER's internal migration system, **shipship**, is a refactored version of the excellent [yoyo-migrations](https://github.com/ollycope/yoyo) library originally by Oliver Cope. 

The name **shipship** is a reference to the **Ship of Theseus** (or Theseus' paradox): a thought experiment that asks whether an object that has had all of its components replaced remains fundamentally the same object.
