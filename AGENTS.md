# Agent Instructions

When working on this project, please note the following tools and conventions used:

## Task Runner (Poe)

This project uses `poe` (Poe the Poet) as its task runner, which is configured in `pyproject.toml`. Poe is set up with `executor = { type = "uv" }`, so executing `poe <task>` automatically runs commands inside the `uv` virtual environment.

Available commands include:

- `poe setup`: Run first-time provisioning setup (certs, secrets, OpenBao)
- `poe up`: Start the complete production service stack using Docker Compose
- `poe dev`: Start the development service stack with live volume bind mounts (`src/`, `migrations/`, `docs/`) and Mailpit/WebhookHub dev services
- `poe dev-down`: Stop the development service stack
- `poe down`: Stop the Docker Compose service stack
- `poe status`: Display container health status and process tree
- `poe restart`: Restart the Docker Compose service stack
- `poe logs`: Tail container logs
- `poe promote-admin <user>`: Promote a user to system_admin role
- `poe reset`: Stop containers and purge persistent database volumes for a clean slate reset
- `poe clean`: Clean test cache (`.pytest_cache`, `.mypy_cache`), coverage, and build artifacts
- `poe db-migrate`: Apply database migrations via Shipship
- `poe test`: Run all tests using `pytest`
- `poe coverage`: Run tests with coverage
- `poe lint`: Run `ruff` to lint the code
- `poe format`: Run `ruff` to format the code
- `poe mypy`: Run `mypy` for static type checking
- `poe vulture`: Run `vulture` to find dead code
- `poe verify`: Run lint, format, vulture, test, and mypy in sequence


## Testing

Tests are located in the `tests/` directory and use `pytest`. You can run them via `poe test`.

## Dependencies

Dependency management is handled via `uv` as defined in `pyproject.toml`.

## Version Control & Commits

This environment uses the **Fish** shell, which does not execute bash-style heredocs (`<<EOF`) or handle nested string quotes the same way Bash does. When generating multi-line git commit messages via the terminal, do **not** use `git commit -m "..." -m "..."` with complex strings, as they often get garbled or truncated.

Instead, write your multi-line commit message to a temporary file, commit it, and remove the file:

```bash
echo "feat(scope): title

- Detail 1
- Detail 2" > .git/commit-msg.tmp
git commit -F .git/commit-msg.tmp
rm .git/commit-msg.tmp
```
