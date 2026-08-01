#!/usr/bin/env bash
# bin/delete-user.sh: Completely remove a user from Authelia and ROVER database.
#
# Usage:
#   ./bin/rover delete-user <username-or-email>
#   or ./bin/create-admin.sh <username-or-email>

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

source "$REPO_ROOT/bin/lib.sh"

QUERY="${1:-}"
[[ -z "$QUERY" ]] && error "Usage: $0 <username-or-email>"

USERNAME=$(echo "$QUERY" | tr '[:upper:]' '[:lower:]' | cut -d'@' -f1)

info "Cleaning up user '${QUERY}'..."

# 1. Remove from Authelia YAML
if [[ -f "authelia/users_database.yml" ]]; then
    python3 -c "
import yaml
path = 'authelia/users_database.yml'
try:
    with open(path, 'r') as f:
        data = yaml.safe_load(f) or {'users': {}}
    if 'users' in data and '$USERNAME' in data['users']:
        del data['users']['$USERNAME']
        with open(path, 'w') as f:
            yaml.safe_dump(data, f, sort_keys=False)
        print('  [Authelia] Removed user entry from authelia/users_database.yml')
except Exception as e:
    print('  [Authelia] Note:', e)
"
    if docker ps --format '{{.Names}}' | grep -q "^authelia$"; then
        docker restart authelia >/dev/null 2>&1 || true
        info "  [Authelia] Restarted Authelia container to reload user database."
    fi
fi

# 2. Remove from ROVER Postgres DB if container is running
if docker ps --format '{{.Names}}' | grep -q "^postgres$"; then
    DB_CMD="docker exec -i postgres psql -U rover -d rover -t -A -c"
    
    $DB_CMD "DELETE FROM api_tokens WHERE user_sub = '${USERNAME}' OR user_sub = '${QUERY}';" >/dev/null 2>&1 || true
    $DB_CMD "DELETE FROM product_users WHERE user_sub = '${USERNAME}' OR user_sub = '${QUERY}';" >/dev/null 2>&1 || true
    $DB_CMD "DELETE FROM user_invites WHERE email = '${QUERY}' OR accepted_by_sub = '${USERNAME}';" >/dev/null 2>&1 || true
    $DB_CMD "DELETE FROM users WHERE sub = '${USERNAME}' OR sub = '${QUERY}' OR email = '${QUERY}';" >/dev/null 2>&1 || true
    info "  [Database] Removed user records from ROVER PostgreSQL database."
else
    warn "Postgres container is not running; skipped database cleanup."
fi

info "User '${QUERY}' has been completely removed."
