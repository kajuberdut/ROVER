# Gemini Instructions

When working on this project, please note the following tools and conventions used:

## Task Runner (Poe)

This project uses `poe` (Poe the Poet) as its task runner, which is configured in `pyproject.toml` (not `pyproject.yaml`). Use `poe` for all common tasks like testing, linting, formatting, and type-checking.

Available commands include:

- `poe test`: Run all tests using `pytest`
- `poe coverage`: Run tests with coverage
- `poe lint`: Run `ruff` to lint the code
- `poe format`: Run `ruff` to format the code
- `poe mypy`: Run `mypy` for static type checking
- `poe vulture`: Run `vulture` to find dead code
- `poe verify`: Run `lint`, `format`, `test`, and `mypy` in sequence

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
