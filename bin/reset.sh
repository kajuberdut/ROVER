#!/usr/bin/env bash
# bin/reset.sh: Safely stop containers and purge persistent database volumes.
#
# Usage:
#   ./bin/reset.sh [--force]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

source "$REPO_ROOT/bin/lib.sh"

FORCE=0
for arg in "$@"; do
    if [[ "$arg" == "--force" || "$arg" == "-f" ]]; then
        FORCE=1
    fi
done

if [[ "$FORCE" -ne 1 ]]; then
    warn "CAUTION: This command will stop containers and PERMANENTLY PURGE all persistent database volumes!"
    if [[ -t 0 ]]; then
        read -rp "Are you sure you want to proceed? [y/N]: " CONFIRM
        if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
            info "Reset cancelled."
            exit 0
        fi
    else
        error "Non-interactive environment detected. Pass '--force' or '-f' to execute volume purge."
    fi
fi

info "Resetting ROVER stack and purging persistent database volumes..."
docker compose --env-file .env.dev -f docker/docker-compose.yml -f docker/docker-compose.dev.yml -p rover down -v --remove-orphans
info "Reset complete. Run 'poe setup' or './bin/rover setup' to re-provision."
