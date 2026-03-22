# ── Stage 1: Build ──────────────────────────────────────────────────────────
# Paper [11] (Jarkas et al.): multi-stage build — TypeScript compiler and all
# dev dependencies never reach the production image.
FROM node:20-alpine AS build

# Paper [13] (Ugale & Potgantwar): apply all available OS patches at build time
# to remediate base-image CVEs before Trivy scanning in CI.
# Upgrade npm itself to pull in patched bundled deps (cross-spawn, glob, tar, minimatch).
RUN apk upgrade --no-cache && npm install -g npm@latest --quiet

WORKDIR /app

# OpenSSL required so prisma generate selects the linux-musl-openssl-3.0.x binary
RUN apk add --no-cache openssl

COPY package.json ./
RUN npm install && npm cache clean --force

COPY . .
RUN npm run prisma:generate
RUN npm run build

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
# Minimal node:20-alpine image — only compiled JS + production node_modules.
# Paper [11]: minimal base image reduces CVE exposure.
# Paper [12]: no shell tools, no package manager access at runtime.
FROM node:20-alpine AS runtime

# Apply OS patches and upgrade npm bundled deps — Paper [13]
RUN apk upgrade --no-cache && npm install -g npm@latest --quiet

# Non-root user — Paper [11] (container escape prevention via non-root execution)
RUN addgroup -S app && adduser -S app -G app

WORKDIR /app

# Install production dependencies only — no TypeScript, no build tools
COPY package.json ./
RUN npm install --omit=dev && npm cache clean --force

# Copy compiled output and generated Prisma client from build stage
COPY --from=build /app/dist                  ./dist
COPY --from=build /app/node_modules/.prisma  ./node_modules/.prisma
COPY --from=build /app/node_modules/@prisma  ./node_modules/@prisma

# Prisma schema needed by the runtime client
COPY --chown=app:app prisma ./prisma

# Startup entrypoint: runs Prisma migrations then starts the server
COPY --chown=app:app docker-entrypoint.sh ./docker-entrypoint.sh
RUN chmod +x docker-entrypoint.sh

# OpenSSL required by the linux-musl-openssl-3.0.x Prisma binary target.
# Create uploads directory before dropping privileges.
RUN apk add --no-cache openssl && \
    mkdir -p /app/uploads/tmp && \
    chown -R app:app /app/uploads

# Paper [11]: drop to non-root for all subsequent operations
USER app

EXPOSE 3001

# start-period accounts for Prisma migration time on first boot.
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD wget -qO- http://localhost:3001/health || exit 1

CMD ["./docker-entrypoint.sh"]
