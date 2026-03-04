# R.O.V.E.R

**R**elease **O**riented **V**ulnerability **E**valuation & **R**eporting

A lightweight, Falcon-backed security dashboard for aggregating and reporting multi-repository vulnerability scans across release tags.

## Getting Started

The project is a Python ASGI backend that renders server-side HTML.

### Installation and Running

You can run the application using Docker Compose (recommended) or locally using [uv](https://github.com/astral-sh/uv).

#### Using Docker Compose (Recommended)

1. Clone the repository and navigate into it.
2. Start the application:
   ```bash
   docker compose up --build
   ```
   Or using Poe the Poet:
   ```bash
   poe compose-up
   ```

#### Local Installation with `uv`

1. Ensure you have `uv` and the Docker daemon running on your system.
2. Clone the repository and navigate into it.
3. Install dependencies and create the virtual environment:
   ```bash
   uv sync
   ```
4. Start the ASGI Server:
   ```bash
   uv run poe rover
   ```
   *(Note: This uses the `poe rover` task defined in `pyproject.toml`)*
5. **Interact via Browser**:
   Navigate to `http://localhost:8000/` to view recent scan jobs, or test checking a repository directly!

### Architecture

- **App Setup**: Falcon ASGI application instance.
- **Routing**: Resource classes mapped to routes for the main dashboard and specific report views.
- **Templating**: Jinja2 environment to load HTML templates from a local directory, complete with deep JSON parsing for vulnerability datasets.
- **Styling**: Includes PicoCSS from `./static/css` in the base HTML template `<head>` for clean, minimal styling.
- **Frontend Interactivity**: Lightweight, dependency-free Vanilla JavaScript is used to handle dynamic UX features like:
  - Background auto-polling of the queue table using the `fetch` API.
  - Floating combo-button navigation on long reports managed via `IntersectionObserver`.
  - Dynamic Git Reference querying (Branches, Tags) using `git ls-remote` coupled to a custom PicoCSS segmented button UI.
- **Job Queue**: A lightweight `sqlite3` queue (`scan_queue.py`) manages asynchronous scanning jobs without needing heavy external message brokers. 
- **Worker Thread**: `worker.py` runs an `asyncio` loop inside a background Python thread alongside Falcon, gracefully picking up jobs from SQLite.
- **Artifact Bundles**: Users can logically group and track multiple Git Repositories and Docker Images together under Release Packages, rolling up all vulnerability metrics into a unified dashboard view.
- **Scanner Execution**: The `scanner.py` utility utilizes `testcontainers` to launch ephemeral, isolated `aquasec/trivy:latest` Docker containers. This ensures no host-system dependencies are needed beyond Docker itself.
  - **Caching**: The application uses a Docker named volume (`trivy-vulnerability-db-cache`) injected securely during scan runtime, caching the heavy 40-200MB vulnerability DB.
