# ROVER Database Refactor Plan

This document tracks the step-by-step progress for replacing the ROVER database layer. The process is broken into three distinct phases to isolate changes and ensure stability.

## Phase 1: SQLAlchemy Core Abstraction (Target: SQLite)
**Goal**: Move away from raw SQL strings to SQLAlchemy Core / Expression Language while keeping the underlying SQLite engine. This isolates query refactoring from the database engine switch.

- [x] Add `sqlalchemy` to `pyproject.toml`.
- [x] Create `src/rover/db/schema.py` to define SQLAlchemy `MetaData` and `Table` objects for all current tables.
- [x] Refactor `scan_queue.py` (or start splitting it as per ROADMAP A3) to use SQLAlchemy Core expressions instead of `conn.execute("SELECT ...")`.
- [x] Ensure SQLite-specific logic (like WAL pragmas) is retained temporarily.
- [x] Run test suite and manual verification to ensure no functional changes.

## Phase 2: PostgreSQL 17 Transition
**Goal**: Swap the underlying database engine from SQLite to PostgreSQL 17.

- [ ] Add `psycopg[binary]` (or `psycopg2-binary`) to `pyproject.toml`.
- [ ] Update `docker-compose.yml` to add a `db` service running `postgres:17`.
- [ ] Configure `web` service to depend on `db` and accept a `DATABASE_URL` environment variable.
- [ ] Update the SQLAlchemy engine initialization to connect to Postgres instead of SQLite.
- [ ] Remove SQLite-specific pragmas.
- [ ] Fix any SQL dialect incompatibilities that SQLAlchemy didn't automatically abstract.
- [ ] Run test suite and verify application functionality against Postgres.

## Phase 3: Vendor Yoyo Migrations & Containerize
**Goal**: Implement a formal schema migration system using a vendored version of `yoyo-migrations`, executed via a dedicated container.

- [ ] Vendor the `yoyo-migrations` codebase into `src/vendor/yoyo` (or similar).
- [ ] Add a `TODO` item to review the vendored yoyo codebase for security and maintenance.
- [ ] Create `src/rover/db/migrations/` and write `0001_initial.sql` using Postgres syntax based on the SQLAlchemy tables.
- [ ] Remove `CREATE TABLE IF NOT EXISTS` logic from application startup.
- [ ] Create a migration script/Dockerfile to run yoyo migrations.
- [ ] Update `docker-compose.yml` to include a `migrations` service that runs before `web`.
- [ ] Update `ROADMAP.md` A4 to reflect the completion of Schema Migrations.

---
*Note: This document should be updated as tasks are completed to serve as a resume point if development is paused.*
