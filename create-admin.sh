#!/usr/bin/env bash
# create-admin.sh — Promote a ROVER user to admin.
#
# Usage:
#   ./create-admin.sh <email-or-sub>
#
# Looks up by email first; if no match, tries a direct sub (UUID) match.
# The user must have logged in at least once (even without email in their profile).
# This script can be re-run at any time to recover lost admin access.

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info() { echo -e "${GREEN}[create-admin]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC}  $*"; }
err()  { echo -e "${RED}[error]${NC} $*"; exit 1; }

QUERY="${1:-}"
[[ -z "$QUERY" ]] && err "Usage: $0 <email-or-sub>"

DB_PATH="${ROVER_DB_PATH:-$(dirname "$0")/src/rover/jobs.db}"
[[ -f "$DB_PATH" ]] || err "Database not found at $DB_PATH. Has ROVER been started at least once?"

require() { command -v "$1" &>/dev/null || err "'$1' is required but not found."; }
require sqlite3

# Show all users to aid debugging
ALL_USERS=$(sqlite3 "$DB_PATH" "SELECT sub, email, name, role FROM users;" 2>/dev/null || true)

if [[ -z "$ALL_USERS" ]]; then
    err "No users found. The user must log in at least once before being promoted."
fi

# Try by email first, then by sub
MATCH=$(sqlite3 "$DB_PATH" "SELECT sub FROM users WHERE email = '${QUERY}' LIMIT 1;" 2>/dev/null || true)

if [[ -z "$MATCH" ]]; then
    # Try partial email match (in case domain differs)
    MATCH=$(sqlite3 "$DB_PATH" "SELECT sub FROM users WHERE email LIKE '%${QUERY}%' LIMIT 1;" 2>/dev/null || true)
fi

if [[ -z "$MATCH" ]]; then
    # Fall back to direct sub match
    MATCH=$(sqlite3 "$DB_PATH" "SELECT sub FROM users WHERE sub = '${QUERY}' LIMIT 1;" 2>/dev/null || true)
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
    warn "Pass the 'sub' value (UUID) shown above, or log in first to create a user record."
    exit 1
fi

sqlite3 "$DB_PATH" "UPDATE users SET role = 'admin' WHERE sub = '${MATCH}';"
info "User with sub '${MATCH}' has been promoted to admin."
