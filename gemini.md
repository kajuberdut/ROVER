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
