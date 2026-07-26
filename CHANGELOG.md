# Changelog

All notable changes to the R.O.V.E.R project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **OpenBao Auto-Unseal Sidecar**: Added `openbao-unseal` sidecar container in `docker-compose.yml` that polls OpenBao's health API and automatically unseals OpenBao using `unseal_key.txt` upon container startup and restarts.
- **Jinja2 Template Test Suite**: Added `tests/test_templates.py` to render all 13 Jinja2 templates in unit tests, ensuring no undefined variables, missing object attributes, or broken references exist.
- **Pytest Configuration**: Added `testpaths = ["tests"]` to `pyproject.toml` so running bare `pytest` automatically isolates test discovery to the `tests/` directory.

### Security
- **OpenBao Key & Secret Sanitation**:
  - Updated `.gitignore` to exclude `openbao_keys.json`, `openbao/config/unseal_key.txt`, `openbao/config/tls/`, and `openbao/data/`.
  - Updated `setup-openbao.py` to strip the `root_token` from `openbao_keys.json` after initialization.
- **AppRole Policy Scoping**: Restricted AppRole policies in `setup-openbao.py` to scoped KV paths (`kv/data/scanner/*`, `kv/data/registry/*`) rather than wildcard `kv/data/*`.
- **AppRole Token TTL Limits**: Configured explicit token TTL limits (`token_ttl="1h"`, `token_max_ttl="4h"`, `secret_id_ttl="1h"`) during AppRole provisioning.

### Refactored
- **Database Layer & Facade Removal**:
  - Removed redundant `src/rover/scan_queue.py` facade file and updated all 15 importing modules across routes, workers, scanners, and tests to import directly from `rover.db`.
  - Defined explicit `__all__` exports in `src/rover/db/__init__.py` to eliminate wildcard imports.

### Documentation & Developer Experience
- **Task Runner Cleanup**: Removed obsolete `poe rover` standalone Uvicorn task from `pyproject.toml` in favor of `poe up`.

- **Instruction File Symlinks**: Replaced duplicate `CLAUDE.md` and `gemini.md` files with symbolic links to `AGENTS.md` to prevent documentation drift.
- **Updated README.md & ROADMAP.md**: Updated `README.md` and `ROADMAP.md` to accurately document PostgreSQL, OpenBao provisioning, admin user promotion (`./create-admin.sh`), and `rover.db` architecture.
- **Punctuation Standardisation**: Standardised punctuation across repository documentation, code comments, and HTML templates.
