#!/usr/bin/env bash
# bin/lib.sh: Shared helpers for ROVER setup and administration scripts.

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

info()  { echo -e "${GREEN}[rover]${NC} $*"; }
warn()  { echo -e "${YELLOW}[warn]${NC}  $*"; }
error() { echo -e "${RED}[error]${NC} $*"; exit 1; }
require() { command -v "$1" &>/dev/null || error "'$1' is required but not found in PATH."; }
