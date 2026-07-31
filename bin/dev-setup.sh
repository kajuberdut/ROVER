#!/usr/bin/env bash
# bin/dev-setup.sh: Development environment setup for ROVER
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "==> Ensuring Git submodules are initialized..."
git submodule update --init --recursive

ENV_DEV="$REPO_ROOT/.env.dev"
if [ ! -f "$ENV_DEV" ] || ! grep -q "MAILPIT_SMTP_PASS" "$ENV_DEV"; then
    echo "==> Generating dev stack credentials in .env.dev..."
    ADMIN_EMAIL="admin@rover.local"
    ADMIN_PASS=$(python3 -c "import secrets; print(secrets.token_urlsafe(16))")
    SMTP_USER="rover"
    SMTP_PASS=$(python3 -c "import secrets; print(secrets.token_urlsafe(16))")
    cat <<EOF > "$ENV_DEV"
# Development Compose Environment Overrides
WEBHOOKHUB_ADMIN_EMAIL=${ADMIN_EMAIL}
WEBHOOKHUB_ADMIN_PASSWORD=${ADMIN_PASS}
MAILPIT_SMTP_USER=${SMTP_USER}
MAILPIT_SMTP_PASS=${SMTP_PASS}
EOF
fi

# Load variables
source "$ENV_DEV"
export WEBHOOKHUB_ADMIN_EMAIL
export WEBHOOKHUB_ADMIN_PASSWORD
export MAILPIT_SMTP_USER
export MAILPIT_SMTP_PASS

echo "==> WebhookHub Dev Credentials:"
echo "    Email:    ${WEBHOOKHUB_ADMIN_EMAIL}"
echo "    Password: ${WEBHOOKHUB_ADMIN_PASSWORD}"
echo "==> Mailpit SMTP Dev Credentials:"
echo "    User:     ${MAILPIT_SMTP_USER}"
echo "    Password: ${MAILPIT_SMTP_PASS}"

# Update docs/starlight/src/content/docs/guides/notifications.md with the generated credentials
export DOCS_FILE="$REPO_ROOT/docs/starlight/src/content/docs/guides/notifications.md"
if [ -f "$DOCS_FILE" ]; then
    python3 - << 'PYEOF'
import os, re
path = os.environ["DOCS_FILE"]
wh_email = os.environ["WEBHOOKHUB_ADMIN_EMAIL"]
wh_password = os.environ["WEBHOOKHUB_ADMIN_PASSWORD"]
mail_user = os.environ["MAILPIT_SMTP_USER"]
mail_pass = os.environ["MAILPIT_SMTP_PASS"]

with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# Update WebhookHub credentials
content = re.sub(
    r"Credentials:\s*`[^`]+`\s*/\s*`[^`]+`",
    f"Credentials: `{wh_email}` / `{wh_password}`",
    content
)

# Update Mailpit SMTP Username & Password lines if present, or format SMTP block
content = re.sub(
    r"-\s*\*\*SMTP Username\*\*:\s*`[^`]+`",
    f"- **SMTP Username**: `{mail_user}`",
    content
)
content = re.sub(
    r"-\s*\*\*SMTP Password\*\*:\s*`[^`]+`",
    f"- **SMTP Password**: `{mail_pass}`",
    content
)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)
PYEOF
fi

# If postgres container is running, ensure dedicated webhookhub database exists
if docker ps --format '{{.Names}}' | grep -q "^postgres$"; then
    echo "==> Ensuring webhookhub database exists in Postgres..."
    docker exec postgres psql -U rover -d rover -c "CREATE DATABASE webhookhub;" 2>/dev/null || true
fi
