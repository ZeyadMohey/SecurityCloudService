# ── Stage 1: Build ──────────────────────────────────────────────────────────
# Paper [11] (Jarkas et al.): multi-stage build excludes dev tooling from the
# production image, shrinking the attack surface.
FROM node:20-alpine AS build

# Paper [13] (Ugale & Potgantwar): apply OS patches before Trivy scanning in CI.
# Upgrade npm itself to pull in patched bundled deps (cross-spawn, glob, tar, minimatch).
RUN apk upgrade --no-cache && npm install -g npm@latest --quiet

WORKDIR /app

COPY package.json ./
RUN npm install && npm cache clean --force

COPY . .
RUN npm run build

# ── Stage 2: Serve ──────────────────────────────────────────────────────────
# Minimal nginx:alpine — no node, no npm, no build tools in production image.
FROM nginx:alpine AS serve

# Apply OS patches — Paper [13]: remediate base-image CVEs before scanning.
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

# Paper [11]: drop to non-root. nginx workers inherit this user.
# Master process runs on port 8080 so no CAP_NET_BIND_SERVICE is needed.
USER nginx

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
