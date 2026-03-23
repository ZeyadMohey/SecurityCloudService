# SecureVault Setup Guide

Step-by-step instructions to get the full stack running from scratch on any machine.

---

## Prerequisites

Install the following before you begin:

| Tool                                                                                                  | Minimum version                        | Check              |
| ----------------------------------------------------------------------------------------------------- | -------------------------------------- | ------------------ |
| [Docker Desktop](https://www.docker.com/products/docker-desktop/) (or Docker Engine + Compose plugin) | Docker 24 · Compose v2                 | `docker --version` |
| [Git](https://git-scm.com/)                                                                           | any recent                             | `git --version`    |
| [OpenSSL](https://www.openssl.org/)                                                                   | any recent (used by `init-secrets.sh`) | `openssl version`  |

> **Windows users:** run all shell commands in **Git Bash** (ships with Git for Windows) `bash` scripts are not compatible with PowerShell or CMD.
> **macOS/Linux:** any terminal works.

---

## 1 Clone the repository

```bash
git clone <repo-url>
cd securevault
```

---

## 2 Generate Docker secrets

The backend needs three secret values at runtime (database password, JWT key, master encryption key). The helper script generates them with `openssl rand`:

```bash
bash scripts/init-secrets.sh
```

This creates `./secrets/` with three files:

```
secrets/
├── db_password.txt      # PostgreSQL password
├── jwt_secret.txt       # JWT signing key (64-byte hex)
└── master_key.txt       # AES-256 master encryption key (32-byte hex)
```

> **Important:** `secrets/` is in `.gitignore` these files are **never committed**. Back them up separately. Losing `master_key.txt` makes all encrypted files permanently unrecoverable.

---

## 3 Start the stack

```bash
bash scripts/start.sh
```

This script:

1. Checks whether secrets already exist (skips generation if they do)
2. Runs `docker compose up --build`

All four services build and start automatically. The ML model is trained during the Docker build no separate step is needed.

To run in the background instead:

```bash
bash scripts/start.sh -d
```

### What gets built

| Service      | Image base           | What happens                                                           |
| ------------ | -------------------- | ---------------------------------------------------------------------- |
| `db`         | `postgres:16-alpine` | Pulls image, no build                                                  |
| `backend`    | `node:20-alpine`     | Compiles TypeScript, runs Prisma migrations on first boot              |
| `ml-service` | `python:3.11-slim`   | Installs packages, **trains CNN-LSTM model** (~2–5 min on first build) |
| `frontend`   | `nginx:alpine`       | Runs `vite build`, serves static files via nginx                       |

> **First build takes 5–10 minutes** due to the ML model training stage. Subsequent builds use the Docker layer cache and are much faster.

---

## 4 Verify all services are healthy

```bash
docker compose ps
```

Expected output (all four `STATUS` fields should show `(healthy)`):

```
NAME                   STATUS
securevault-db         Up X seconds (healthy)
securevault-backend    Up X seconds (healthy)
securevault-ml         Up X seconds (healthy)
securevault-frontend   Up X seconds (healthy)
```

Check the enhanced health endpoint:

```bash
curl http://localhost:3001/health
```

Expected response:

```json
{
  "status": "ok",
  "timestamp": "...",
  "version": "1.0.0",
  "services": {
    "database": { "status": "ok" },
    "mlService": { "status": "ok" }
  }
}
```

---

## 5 Open the app

| URL                          | Description                    |
| ---------------------------- | ------------------------------ |
| http://localhost             | Frontend (React SPA via nginx) |
| http://localhost:3001        | Backend API (Express)          |
| http://localhost:3001/health | Health check (DB + ML status)  |

Register an account, upload a file, share it with another user, and download it.

---

## Stopping and restarting

```bash
# Stop (keeps data volumes)
docker compose down

# Stop and wipe the database + uploads
docker compose down -v

# Restart with cached images (fast)
docker compose up -d

# Rebuild all images (e.g. after a code change)
docker compose up --build -d
```

---

## Running the test suite

### Unit tests (no database required runs on the host)

```bash
cd backend
npm install
npm run test:unit
```

Tests `encryption.test.ts` (AES-256-GCM, ECDH, integrity) and `xss-scanner.test.ts` (CNN-LSTM mock). No Docker needed.

### Full test suite (requires the stack to be running)

The integration tests (`auth.test.ts`, `sharing.test.ts`) hit the real database. The stack must be up first (`bash scripts/start.sh -d`).

```bash
cd backend
npm install
npm test
```

The database is exposed on `127.0.0.1:5433` for host-side test runs. Connection string is set automatically in `jest.setup.ts`.

### Run inside Docker (alternative)

```bash
docker compose --profile test run --rm backend-test
```

---

## Environment variables

The Docker stack is fully self-contained you do **not** need to create any `.env` files to run with Docker.

`.env` files are only needed if you run services directly on the host (outside Docker):

```bash
# Backend (host-only dev)
cp backend/.env.example backend/.env
# Edit backend/.env if needed

# Frontend (host-only dev)
cp frontend/.env.example frontend/.env
```

See `backend/.env.example` and `frontend/.env.example` for all available variables and their descriptions.

---

## Production deployment

```bash
# 1. Generate secrets (if not already done)
bash scripts/init-secrets.sh

# 2. Start with production overrides (Docker Secrets, no plaintext env vars)
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

The `docker-compose.prod.yml` overlay:

- Mounts `secrets/*.txt` as Docker Secrets (`/run/secrets/*` inside containers)
- Sets `NODE_ENV=production`
- Replaces the hardcoded dev DB password with the secret file value

---

## Troubleshooting

### Port conflicts

| Error                                       | Fix                                                                                                                                              |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `bind: address already in use` on port 80   | Another web server is using port 80. Stop it or change the frontend port mapping in `docker-compose.yml` (`'8080:8080'` instead of `'80:8080'`). |
| `bind: address already in use` on port 3001 | Something is already on 3001. Change backend mapping to `'3002:3001'` and update `frontend/.env` → `VITE_API_URL=http://localhost:3002`.         |

### Backend fails to start ("Migration failed")

```bash
docker compose logs backend
```

If you see a Prisma migration error, run migrations manually:

```bash
docker compose exec backend npx prisma migrate deploy
```

### ML service takes too long to become healthy

The first build trains the CNN-LSTM model. If the `ml-service` container stays in `(health: starting)` for more than 5 minutes:

```bash
docker compose logs ml-service
```

Training output is visible in the build log. It completes once you see `Model saved.`.

### Reset everything and start fresh

```bash
docker compose down -v          # remove containers + volumes
docker system prune -f          # remove unused images and cache
rm -rf secrets/                 # remove generated secrets
bash scripts/start.sh           # full rebuild from scratch
```

> **Warning:** `docker compose down -v` deletes the database volume all uploaded files and user accounts are lost.

---

## Project structure (quick reference)

```
securevault/
├── scripts/
│   ├── start.sh            ← one-command startup (run this first)
│   └── init-secrets.sh     ← generates secrets/
├── backend/
│   ├── .env.example        ← copy to .env for host-only dev
│   └── src/
├── frontend/
│   ├── .env.example        ← copy to .env for host-only dev
│   └── src/
├── ml-service/             ← CNN-LSTM XSS detection (trained at build time)
├── docker-compose.yml      ← development stack
├── docker-compose.prod.yml ← production overrides (Docker Secrets)
├── secrets/                ← generated by init-secrets.sh (gitignored)
└── docs/SECURITY.md        ← full security architecture & paper citations
```
