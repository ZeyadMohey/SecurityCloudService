# ── Stage 1: Build ──────────────────────────────────────────────────────────
# Multi-stage build: dev tooling excluded from the production image.
FROM node:20-alpine AS build

# Patch OS packages and upgrade npm to pull in updated bundled deps.
RUN apk upgrade --no-cache && npm install -g npm@latest --quiet

WORKDIR /app

COPY package.json ./
RUN npm install && npm cache clean --force

COPY . .
RUN npm run build

# ── Stage 2: Serve ──────────────────────────────────────────────────────────
# Minimal nginx:alpine   no node, no npm, no build tools in production image.
FROM nginx:alpine AS serve

# Patch OS packages.
RUN apk upgrade --no-cache

# Pre-create directories needed by nginx when running as non-root.
# /tmp is used for all runtime temp files (pid, proxy buffers, client body).
# /var/cache/nginx and /var/log/nginx must be writable by the nginx user.
RUN mkdir -p /tmp/nginx /var/cache/nginx /var/log/nginx && \
    chown -R nginx:nginx /tmp/nginx /var/cache/nginx /var/log/nginx && \
    touch /tmp/nginx.pid && \
    chown nginx:nginx /tmp/nginx.pid

# Replace default config with hardened config (security headers, non-root port)
COPY nginx.conf /etc/nginx/nginx.conf

# Copy the Vite production build
COPY --from=build --chown=nginx:nginx /app/dist /usr/share/nginx/html

# Run as non-root. Port 8080 requires no CAP_NET_BIND_SERVICE.
USER nginx

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
