# ROVER CLI

A lightweight, pure-Python command-line client for interacting with the ROVER API.

## Installation

Because this CLI uses only the Python standard library, it can be installed without any external dependencies.

```bash
pip install .
```

## Authentication

The CLI requires an API token to communicate with the ROVER server. You can provide this token in two ways:
1.  **Environment Variable:** Set the `ROVER_API_TOKEN` environment variable.
2.  **Command-Line Flag:** Use the `--token` option.

If you don't specify the ROVER server URL, it defaults to `http://localhost:8000`. You can override this using the `ROVER_URL` environment variable or the `--url` flag.

## Commands

### `publish-metadata`

Publishes CI image metadata to ROVER.

```bash
rover-cli publish-metadata \
    --hash "sha256:1234567890abcdef" \
    --repo "https://github.com/organization/repo" \
    --commit "abc123def456" \
    --job-url "https://ci.example.com/job/123" \
    --tags "latest,v1.0.0"
```
