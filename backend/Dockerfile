# ── Stage 1: Build ──────────────────────────────────────────────────────────
# Multi-stage build: TypeScript compiler and dev dependencies never reach prod.
FROM node:20-alpine AS build

# Patch OS packages and upgrade npm to pull in updated bundled deps.
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
# Minimal image   only compiled JS and production node_modules.
FROM node:20-alpine AS runtime

# Patch OS packages and upgrade npm bundled deps.
RUN apk upgrade --no-cache && npm install -g npm@latest --quiet

# Run as non-root user to limit container escape impact.
RUN addgroup -S app && adduser -S app -G app

WORKDIR /app

# Install production dependencies only   no TypeScript, no build tools
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

USER app

EXPOSE 3001

# start-period accounts for Prisma migration time on first boot.
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD wget -qO- http://localhost:3001/health || exit 1

CMD ["./docker-entrypoint.sh"]
