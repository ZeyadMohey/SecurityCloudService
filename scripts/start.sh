#!/usr/bin/env bash
# start.sh   One-command local deployment for SecureVault.
#
# Usage:
#   bash scripts/start.sh          # build + start (foreground)
#   bash scripts/start.sh -d       # build + start in background
#
# What this script does:
#   1. Generates Docker Secrets (db_password, jwt_secret, master_key) if absent.
#   2. Starts the full stack with docker compose up --build.
#
# ML model training is performed automatically inside the ml-service Docker
# build (see ml-service/Dockerfile train stage)   no separate step required.
#
# Prerequisites: Docker Desktop (or Docker Engine + Compose plugin) running.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

# ── Step 1: Docker Secrets ────────────────────────────────────────────────────
if [ ! -d "secrets" ] || [ ! -f "secrets/db_password.txt" ]; then
  echo "[start] Generating Docker secrets..."
  bash scripts/init-secrets.sh
else
  echo "[start] Secrets already exist   skipping generation."
fi

# ── Step 2: Build and start ───────────────────────────────────────────────────
echo "[start] Starting SecureVault stack (this may take a few minutes on first run)..."
echo ""
echo "  Frontend  : http://localhost"
echo "  Backend   : http://localhost:3001"
echo "  Health    : http://localhost:3001/health"
echo ""

docker compose up --build "$@"
