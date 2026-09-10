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

### `audit-logs`

Retrieves and filters system audit log entries from `/api/admin/audit_logs` (requires `system_admin` privileges).

```bash
# Retrieve recent audit logs in tabular format
rover-cli audit-logs --limit 20

# Filter logs by action and output raw JSON
rover-cli audit-logs --action user.invite_create --json

# Filter logs by resource type and ID
rover-cli audit-logs --resource-type user_invite --resource-id <invite_id>
```
