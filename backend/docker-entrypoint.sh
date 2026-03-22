#!/bin/sh
# docker-entrypoint.sh
#
# Applies any pending Prisma migrations, then starts the Express server.
# Runs as non-root user (app) — Paper [11].
#
# Usage: automatically invoked as the container CMD.

set -e

echo "[entrypoint] Applying database migrations..."
./node_modules/.bin/prisma migrate deploy

echo "[entrypoint] Migrations applied. Starting SecureVault backend..."
exec node dist/index.js
