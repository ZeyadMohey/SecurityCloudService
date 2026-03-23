#!/bin/sh
# Applies any pending Prisma migrations, then starts the Express server.

set -e

echo "[entrypoint] Applying database migrations..."
./node_modules/.bin/prisma migrate deploy

echo "[entrypoint] Migrations applied. Starting SecureVault backend..."
exec node dist/index.js
