#!/usr/bin/env bash
# init-secrets.sh   Generate random Docker Secrets for local deployment.
#
# Secrets are mounted as files at /run/secrets/<name> in containers   never
# exposed as env vars, never visible in `docker inspect`.
#
# Usage:
#   chmod +x scripts/init-secrets.sh
#   ./scripts/init-secrets.sh
#
# The ./secrets/ directory is gitignored   never commit these files.
# For CI/CD, inject them via your secrets manager (GitHub Secrets, Vault, etc.).

set -euo pipefail

SECRETS_DIR="$(cd "$(dirname "$0")/.." && pwd)/secrets"
mkdir -p "$SECRETS_DIR"

# Restrict directory to owner-only immediately
chmod 700 "$SECRETS_DIR"

echo "Generating secrets in $SECRETS_DIR …"

# Database password   32 random bytes (hex), used by PostgreSQL and DATABASE_URL
openssl rand -hex 32 > "$SECRETS_DIR/db_password.txt"
chmod 600 "$SECRETS_DIR/db_password.txt"
echo "  ✓ db_password.txt"

# JWT signing key   64 random bytes (hex), HS256 minimum is 32 bytes
openssl rand -hex 64 > "$SECRETS_DIR/jwt_secret.txt"
chmod 600 "$SECRETS_DIR/jwt_secret.txt"
echo "  ✓ jwt_secret.txt"

# Master encryption key   32 random bytes (hex), used for AES-256-GCM key wrapping
openssl rand -hex 32 > "$SECRETS_DIR/master_key.txt"
chmod 600 "$SECRETS_DIR/master_key.txt"
echo "  ✓ master_key.txt"

echo ""
echo "Secrets generated in $SECRETS_DIR/"
echo ""
echo "WARNING: These files are sensitive. Verify .gitignore includes 'secrets/'."
echo "WARNING: Back them up securely   losing them makes encrypted files unrecoverable."
