#!/usr/bin/env bash
# bin/create-admin.sh: Promote a ROVER user to admin.
#
# Usage:
#   ./bin/rover promote-admin <email-or-sub>
#   or ./bin/create-admin.sh <email-or-sub>

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

source "$REPO_ROOT/bin/lib.sh"

QUERY="${1:-}"
[[ -z "$QUERY" ]] && error "Usage: $0 <email-or-sub>"

require docker

# Check if postgres container is running
if ! docker ps --format '{{.Names}}' | grep -q "^postgres$"; then
    error "Postgres container 'postgres' is not running. Please start the database first via './bin/rover up'."
fi

# Run command inside postgres container
DB_CMD="docker exec -i postgres psql -U rover -d rover -t -A -c"

# Show all users to aid debugging
ALL_USERS=$($DB_CMD "SELECT sub || '|' || COALESCE(email, '') || '|' || COALESCE(name, '') || '|' || role FROM users;" 2>/dev/null || true)

if [[ -z "$ALL_USERS" ]]; then
    error "No users found in ROVER database. The user must log in at https://rover.local at least once before being promoted."
fi

# Try by email first, then by sub
MATCH=$($DB_CMD "SELECT sub FROM users WHERE email = '${QUERY}' LIMIT 1;" 2>/dev/null || true)

if [[ -z "$MATCH" ]]; then
    # Try partial email match
    MATCH=$($DB_CMD "SELECT sub FROM users WHERE email LIKE '%${QUERY}%' LIMIT 1;" 2>/dev/null || true)
fi

if [[ -z "$MATCH" ]]; then
    # Fall back to direct sub match
    MATCH=$($DB_CMD "SELECT sub FROM users WHERE sub = '${QUERY}' LIMIT 1;" 2>/dev/null || true)
fi

if [[ -z "$MATCH" ]]; then
    warn "No user found matching '${QUERY}'."
    echo ""
    warn "Existing users in the database:"
    echo "$ALL_USERS" | while IFS='|' read -r sub email name role; do
        echo "  sub:   ${sub}"
        echo "  email: ${email:-<none>}"
        echo "  name:  ${name:-<none>}"
        echo "  role:  ${role}"
        echo ""
    done
    error "Pass the 'sub' UUID shown above or log in first to create a user record."
fi

$DB_CMD "UPDATE users SET role = 'system_admin' WHERE sub = '${MATCH}';" >/dev/null
info "User with sub '${MATCH}' has been promoted to system_admin."
