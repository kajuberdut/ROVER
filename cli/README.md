# ROVER CLI

A lightweight, pure-Python command-line client for interacting with the ROVER API.

## Installation

Because this CLI uses only the Python standard library, it can be installed without any external dependencies.

```bash
pip install .
```

## Authentication & SSL Verification

The CLI requires an API token to communicate with the ROVER server. You can provide configuration options via environment variables or command-line flags:

1. **Authentication Token:**
   - Environment Variable: `ROVER_API_TOKEN`
   - Command-Line Flag: `--token`

2. **ROVER Server URL:**
   - Environment Variable: `ROVER_URL` (defaults to `http://localhost:8000`)
   - Command-Line Flag: `--url`

3. **Insecure SSL / Self-Signed Certificates:**
   - If connecting to local development or testing environments using self-signed TLS certificates (e.g. `https://rover.local`), skip TLS verification with:
   - Command-Line Flag: `--insecure` or `-k`
   - Environment Variable: `ROVER_INSECURE=true` or `ROVER_SKIP_TLS_VERIFY=true`

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
# Retrieve recent audit logs in tabular format over self-signed HTTPS
rover-cli --token <token> --url https://rover.local -k audit

# Filter logs by action and output raw JSON
rover-cli audit-logs --action user.invite_create --json

# Filter logs by resource type and ID
rover-cli audit-logs --resource-type user_invite --resource-id <invite_id>
```
