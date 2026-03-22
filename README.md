# SecureVault

A security-focused cloud file storage and sharing system demonstrating defence-in-depth across every architectural layer: frontend, backend, DevOps. Each security control is grounded in one or more of 15 peer-reviewed research papers.

## Quick Start

```bash
# Clone and start (Docker Desktop required)
git clone <repo-url> && cd securevault
bash scripts/start.sh
```

Open **http://localhost** in your browser.

| Service   | URL                          |
|-----------|------------------------------|
| Frontend  | http://localhost             |
| Backend   | http://localhost:3001        |
| Health    | http://localhost:3001/health |

> `scripts/start.sh` generates Docker Secrets on first run, then calls `docker compose up --build`. ML model training is baked into the image build — no separate step needed.

---

## Architecture

```
Browser
  │  HTTPS (TLS 1.3 in prod) / HTTP in dev
  ▼
┌─────────────────────────────────────────┐  frontend-net
│  Frontend  (nginx:alpine, port 80)      │◄──────────────
│  React 18 + Vite + TailwindCSS          │
│  • DOMPurify sanitisation  [Papers 1,2] │
│  • CSP nonce per request   [Paper 5]    │
│  • Sandboxed file preview  [Paper 2]    │
└────────────┬────────────────────────────┘
             │  /api/*  (proxy)           backend-net
             ▼
┌─────────────────────────────────────────┐
│  Backend   (node:20-alpine, port 3001)  │
│  Node.js + Express + TypeScript         │
│  • AES-256-GCM file encryption [Pp 6,7] │
│  • Per-file keys               [Paper 10│
│  • ECDH key exchange           [Paper 9]│
│  • SHA-256 integrity hash      [Paper 8]│
│  • PBKDF2 master key           [Paper 6]│
│  • Rate limiting + Helmet               │
└──────┬─────────────┬─────────────────────┘
       │  db-net      │  ml-net
       │  (internal)  │  (internal)
       ▼              ▼
┌────────────┐  ┌──────────────────────────┐
│ PostgreSQL │  │  ML Service              │
│ (port 5432)│  │  (python:3.11-slim, 8000)│
│ Prisma ORM │  │  FastAPI + CNN-LSTM model │
│            │  │  XSS detection [Pp 3,4]  │
└────────────┘  └──────────────────────────┘

Network segments (Paper [12]):
  frontend-net  — browser → nginx only
  backend-net   — nginx → Express only
  db-net        — Express → PostgreSQL only  (internal: true)
  ml-net        — Express → ML service only  (internal: true)
```

---

## Security Features

| Feature | Implementation | Papers |
|---------|---------------|--------|
| **Input sanitisation** | DOMPurify (client) + allowlist regex (server) | [1] Hannousse, [2] Kaur |
| **DL-based XSS detection** | CNN-LSTM on Kaggle XSS dataset, char-level tokens | [3] Tadhani, [4] Li |
| **CSP nonce rotation** | `crypto.randomBytes(16)` per response, never cached | [5] Knittel |
| **AES-256-GCM encryption** | File-at-rest with authenticated encryption (not ECB) | [6] Boneh, [7] Bhavani |
| **MEGA vulnerability fix** | GCM auth-tag rejection on ciphertext tampering | [7] Bhavani |
| **SHA-256 integrity** | `timingSafeEqual` hash comparison on every download | [8] Zhu |
| **ECC key exchange** | ECDH(secp256k1) + HKDF for share key derivation | [9] Abualkas |
| **Per-file encryption keys** | Each file gets a unique random 256-bit key | [10] EStore |
| **Hardened containers** | Alpine base, non-root user, `read_only`, tmpfs | [11] Jarkas |
| **Network isolation** | 4 custom bridge networks, db/ml marked `internal` | [12] Lee |
| **CVE scanning** | Trivy `--severity HIGH,CRITICAL --exit-code 1` in CI | [13] Ugale |
| **Secrets detection** | Gitleaks pre-commit hook + CI gate | [14] Prates |
| **Docker Secrets** | `/run/secrets/` mount — no plaintext in env vars | [15] Sinan |

---

## User Flow

```
Register  →  ECDH key pair generated, private key encrypted with PBKDF2 master key
Login     →  JWT issued, PBKDF2 salt returned for client master-key derivation
Upload    →  File scanned by CNN-LSTM XSS model → AES-256-GCM encrypted → SHA-256 hashed
Share     →  ECDH(A_priv, B_pub) → HKDF → AES-GCM re-wrap of file key
Download  →  AES-256-GCM decrypt → SHA-256 integrity verified → file returned
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, Vite, TypeScript, TailwindCSS, DOMPurify |
| Backend | Node.js 20, Express, TypeScript, Prisma ORM |
| Database | PostgreSQL 16 |
| ML service | Python 3.11, FastAPI, TensorFlow 2, CNN-LSTM |
| Containers | Docker, Docker Compose, Alpine Linux |
| CI/CD | GitHub Actions (4 sequential security gates) |

---

## Running Tests

```bash
# Unit tests (no database required) — runs on the host
cd backend && npm run test:unit

# Full test suite (requires running stack)
docker compose --profile test run --rm backend-test

# Individual test suites
npx jest --testPathPatterns=auth
npx jest --testPathPatterns=encryption
npx jest --testPathPatterns=xss-scanner
npx jest --testPathPatterns=sharing
```

---

## CI/CD Pipeline

Four sequential security gates (Papers [13], [14]):

```
push / PR
  │
  ▼
[Gate 1] Secrets Scan      — Gitleaks full-history scan
  │
  ▼
[Gate 2] Lint & SAST       — ESLint + npm audit + tsc --noEmit
  │
  ├──▶ [Gate 2b] Backend Tests — Jest 39 tests (postgres service)
  │
  ▼
[Gate 3] Build & Scan      — Docker Buildx + Trivy HIGH/CRITICAL
  │
  ▼
[Gate 4] Integration Tests — docker compose up, health checks,
                             network isolation verification
```

---

## Project Structure

```
securevault/
├── frontend/          React + Vite SPA
│   └── src/
│       ├── pages/     Login, Register, Dashboard
│       ├── components/
│       └── utils/     DOMPurify sanitiser, client-side crypto
├── backend/           Express API
│   └── src/
│       ├── routes/    auth, files, share, users
│       ├── services/  encryption, keySharing, xss-scanner
│       ├── middleware/ auth JWT, CSP nonce, XSS scan
│       └── utils/     crypto helpers, sanitiser
├── ml-service/        FastAPI + CNN-LSTM XSS detection
│   └── app/           main.py, model.py, train.py
├── scripts/
│   ├── start.sh       One-command startup
│   └── init-secrets.sh  Docker Secrets generator
├── docs/
│   └── SECURITY.md    Full security architecture (all 15 papers)
├── docker-compose.yml
└── .github/workflows/security-pipeline.yml
```

---

## Setup Details

### Prerequisites
- Docker Desktop 4.x (or Docker Engine + Compose plugin)
- Ports 80 and 3001 free on the host

### First-time setup
```bash
bash scripts/start.sh          # generates secrets + builds + starts
```

### Subsequent starts
```bash
docker compose up              # use cached images
docker compose up --build      # rebuild images
```

### Database migrations
Migrations run automatically on backend startup via `docker-entrypoint.sh`.
To run manually:
```bash
docker compose exec backend npx prisma migrate dev
```

### Production deployment
```bash
bash scripts/init-secrets.sh   # generates ./secrets/*.txt
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

---

## Team

| Name | Role |
|------|------|
| [Member 1] | Backend & Encryption |
| [Member 2] | Frontend & XSS Prevention |
| [Member 3] | ML Service & Model Training |
| [Member 4] | DevOps & Container Security |

---

## References

Full paper citations are in [`docs/SECURITY.md`](docs/SECURITY.md).
