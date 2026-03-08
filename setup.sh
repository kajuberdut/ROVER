#!/usr/bin/env bash
# setup.sh — First-time provisioning for ROVER
# Generates TLS certs, secrets, and Authelia config from templates.
# Safe to re-run; will not overwrite existing files by default.

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}[setup]${NC} $*"; }
warn()    { echo -e "${YELLOW}[warn]${NC}  $*"; }
require() { command -v "$1" &>/dev/null || { echo -e "${RED}[error]${NC} '$1' is required but not found."; exit 1; }; }

require openssl
require docker

# ── 1. Nginx TLS certificates ───────────────────────────────────────────────
CERT_DIR="nginx/certs"
if [[ -f "$CERT_DIR/rover.local.crt" ]]; then
    warn "TLS cert already exists at $CERT_DIR/rover.local.crt — skipping."
else
    info "Generating self-signed TLS certificate for *.rover.local ..."
    mkdir -p "$CERT_DIR"
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$CERT_DIR/rover.local.key" \
        -out    "$CERT_DIR/rover.local.crt" \
        -subj   "/CN=*.rover.local" 2>/dev/null
    info "Certificate written to $CERT_DIR/"
fi

# ── 2. Authelia secrets ──────────────────────────────────────────────────────
if [[ -f "authelia/configuration.yml" ]]; then
    warn "authelia/configuration.yml already exists — skipping secret generation."
else
    info "Generating Authelia secrets ..."

    JWT_SECRET=$(openssl rand -hex 32)
    SESSION_SECRET=$(openssl rand -hex 32)
    STORAGE_KEY=$(openssl rand -hex 32)$(openssl rand -hex 32)  # 64-char minimum
    HMAC_SECRET=$(openssl rand -hex 48)

    info "Generating RSA private key for OIDC JWK ..."
    RSA_KEY=$(openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 2>/dev/null)

    # Indent each line of the key by 10 spaces to fit the YAML block scalar
    INDENTED_KEY=$(echo "$RSA_KEY" | sed 's/^/          /')

    info "Generating OIDC client secret ..."
    CLIENT_SECRET_PLAIN=$(openssl rand -hex 24)
    CLIENT_SECRET_HASH=$(docker run --rm authelia/authelia:latest \
        authelia crypto hash generate argon2 --password "$CLIENT_SECRET_PLAIN" 2>/dev/null \
        | grep -o '\$argon2.*')

    info "Writing authelia/configuration.yml ..."
    sed \
        -e "s|PLACEHOLDER_JWT_SECRET|${JWT_SECRET}|g" \
        -e "s|PLACEHOLDER_SESSION_SECRET|${SESSION_SECRET}|g" \
        -e "s|PLACEHOLDER_STORAGE_ENCRYPTION_KEY|${STORAGE_KEY}|g" \
        -e "s|PLACEHOLDER_HMAC_SECRET|${HMAC_SECRET}|g" \
        -e "s|PLACEHOLDER_CLIENT_SECRET_HASH|\$plaintext\$${CLIENT_SECRET_PLAIN}|g" \
        authelia/configuration.yml.example > authelia/configuration.yml

    # Replace the multiline RSA key placeholder
    python3 - <<PYEOF
import re, sys
path = "authelia/configuration.yml"
content = open(path).read()
key_block = '''${INDENTED_KEY}'''
content = content.replace("          PLACEHOLDER_RSA_PRIVATE_KEY", key_block)
open(path, "w").write(content)
PYEOF

    info "Client secret (plaintext — used in auth.py OIDC_CLIENT_SECRET): ${CLIENT_SECRET_PLAIN}"
    warn "Store this secret securely. It will not be shown again."
    echo "ROVER_OIDC_CLIENT_SECRET=${CLIENT_SECRET_PLAIN}" >> .env.local
    info "Also written to .env.local"
fi

# ── 3. Authelia user database ────────────────────────────────────────────────
if [[ -f "authelia/users_database.yml" ]]; then
    warn "authelia/users_database.yml already exists — skipping."
else
    echo ""
    info "Creating the initial admin user."
    read -rsp "Enter password for 'admin': " ADMIN_PASS
    echo ""

    info "Hashing password with Argon2 (this may take a moment) ..."
    ADMIN_HASH=$(docker run --rm authelia/authelia:latest \
        authelia crypto hash generate argon2 --password "$ADMIN_PASS" 2>/dev/null \
        | grep -o '\$argon2.*')

    sed "s|PLACEHOLDER_ADMIN_PASSWORD_HASH|${ADMIN_HASH}|g" \
        authelia/users_database.yml.example > authelia/users_database.yml

    info "authelia/users_database.yml written."
fi

# ── 4. /etc/hosts reminder ───────────────────────────────────────────────────
if ! grep -q "rover.local" /etc/hosts 2>/dev/null; then
    echo ""
    warn "Add these entries to /etc/hosts to resolve the local domains:"
    echo "    127.0.0.1 rover.local auth.rover.local"
fi

echo ""
info "Setup complete. Run: docker compose up --build -d"
info "Then navigate to: https://rover.local"
