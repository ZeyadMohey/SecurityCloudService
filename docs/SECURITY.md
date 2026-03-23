# SecureVault Security Architecture

This document describes the security architecture of SecureVault, a cloud file storage and sharing system. Every security control is grounded in one or more of the 15 academic papers listed in the bibliography. The document also covers the threat model, how to run security scans locally, and the CI/CD security pipeline.

---

## Table of Contents

1. [Threat Model](#threat-model)
2. [Frontend Security XSS Prevention & Detection](#frontend-security)
3. [Backend Security Encryption & Integrity](#backend-security)
4. [DevOps Security Container & CI/CD](#devops-security)
5. [Running Security Scans Locally](#running-scans)
6. [Bibliography](#bibliography)

---

## 1. Threat Model {#threat-model}

### Assets

| Asset                | Sensitivity            | Location                                        |
| -------------------- | ---------------------- | ----------------------------------------------- |
| File contents        | High user private data | AES-256-GCM encrypted at rest                   |
| File encryption keys | Critical               | Encrypted with user master key, stored in DB    |
| User master keys     | Critical               | Never stored; derived per-session from password |
| ECDH private keys    | Critical               | AES-256-GCM encrypted, stored in DB             |
| JWT tokens           | High                   | Short-lived (24h), HS256 signed                 |
| Filenames / metadata | Medium                 | Sanitized, ML-scanned, HTML-encoded on display  |

### Attacker Profiles

| Threat Actor              | Capability | Primary Attack Vector                                  |
| ------------------------- | ---------- | ------------------------------------------------------ |
| External attacker         | Low–medium | XSS via malicious filename, brute-force login          |
| Malicious file sharer     | Medium     | XSS payload in filename/metadata targeting other users |
| Compromised container     | High       | Lateral movement to DB or other services               |
| Supply-chain attacker     | High       | Vulnerable dependency, malicious base image            |
| Insider / compromised dev | High       | Accidentally committed credentials                     |

### Risk Controls Summary

| Risk                         | Control                                                  | Paper Reference     |
| ---------------------------- | -------------------------------------------------------- | ------------------- |
| XSS via uploaded filenames   | ML detection + allowlist sanitizer + CSP nonce           | [1], [3], [4], [5]  |
| XSS via shared file metadata | DOMPurify client-side + HTML entity encoding server-side | [1], [2]            |
| File content exposure        | AES-256-GCM per-file encryption, integrity hash          | [6], [7], [8], [10] |
| Unauthorised file access     | ECDH shared-secret key wrapping, JWT auth                | [9]                 |
| Container escape             | Non-root users, read-only FS, no-new-privileges          | [11]                |
| Lateral movement             | Custom Docker networks, internal networks for DB/ML      | [12]                |
| Vulnerable images            | Trivy CVE scanning in CI, Alpine base images             | [13]                |
| Leaked credentials in code   | Gitleaks pre-commit + CI gate                            | [14]                |
| Secrets in environment vars  | Docker Secrets, /run/secrets/ at runtime                 | [15]                |

---

## 2. Frontend Security XSS Prevention & Detection {#frontend-security}

### 2.1 Layered XSS Defence Papers [1] and [2]

Hannousse & Yahiouche [1] found that 84.71% of XSS research targets only reflected/stored XSS; DOM-based and mutation-based variants are under-addressed. Kaur et al. [2] recommend a layered approach: input validation → output encoding → CSP, applied at every layer.

SecureVault implements four defence layers:

1. **Client-side sanitization** DOMPurify strips all HTML from server-sourced strings before rendering.
2. **Server-side allowlist sanitization** (`backend/src/utils/sanitizer.ts`) `sanitizeFilename()` permits only `[A-Za-z0-9.\-_ ]`, collapsing path traversal sequences (`..`). `encodeHtml()` entity-encodes six dangerous characters for HTML context.
3. **ML-based detection** (`ml-service/`) CNN-LSTM model classifies filenames and metadata; confidence > 0.7 rejects the upload with HTTP 400.
4. **CSP nonce** Every HTML response carries a per-request nonce; `script-src 'nonce-{nonce}'` blocks inline scripts not approved by the server.

### 2.2 CNN-LSTM XSS Detection Papers [3] and [4]

Tadhani et al. [3] demonstrate that a CNN-LSTM hybrid extracts both local n-gram features (CNN) and sequential attack patterns (LSTM) from HTTP payloads. Li et al. [4] show that character-level tokenization outperforms word-level methods because XSS payloads exploit character-level obfuscation (`%3Cscript`, `\u003cscript`).

**Implementation** (`ml-service/app/model.py`):

```
Input (200 chars) → Embedding(64) → Conv1D(128, k=3) → MaxPool → BiLSTM(64) → Dense(64) → Dropout(0.5) → Sigmoid
```

- Character-level tokenization (vocab ≈ 137 chars for ASCII payloads)
- Trained on 521-sample dataset: 251 XSS / 270 benign (test accuracy 1.0)
- Threshold 0.7 for rejection (configurable in `xss-scan.ts`)

### 2.3 CSP Nonce Rotation Paper [5]

Knittel et al. [5] found that many production sites reuse CSP nonces due to CDN or load balancer caching, completely nullifying CSP. SecureVault addresses this directly:

- **Per-request generation** (`backend/src/middleware/cspNonce.ts`): `crypto.randomBytes(16).toString('base64')` on every request.
- **No caching**: `Cache-Control: no-store` on all responses prevents CDN/proxy nonce capture.
- **Verification**: tested in CI two consecutive requests must return different nonces.

### 2.4 Sandboxed File Preview Paper [2]

File previews render in `<iframe sandbox="allow-same-origin">` elements no scripts, no parent DOM access, no cookie access. This limits the blast radius of any XSS that bypasses detection layers.

---

## 3. Backend Security Encryption & Integrity {#backend-security}

### 3.1 AES-256-GCM File Encryption Papers [6] and [7]

Backendal et al. [7] (MEGA analysis) demonstrated that AES-ECB mode allows plaintext block pattern recovery and, combined with key reuse, enabled private key extraction after ~512 observed logins. SecureVault explicitly avoids these mistakes:

- **AES-256-GCM** (not ECB): authenticated encryption ciphertext + auth tag, 96-bit random IV per operation.
- **No IV reuse**: `crypto.randomBytes(12)` generated fresh for every `gcmEncryptBuffer()` call.
- **Auth tag verification**: `decipher.setAuthTag()` on every decrypt rejects tampered ciphertext.
- Shivaramakrishna & Nagaratna [6] advocate dual-layer encryption (symmetric for data, asymmetric for key exchange) implemented via AES-256-GCM for files and ECDH for key sharing.

### 3.2 Per-File Encryption Keys Paper [10]

Chen et al. [10] identify that single-key-for-all-files schemes mean a single breach exposes the entire vault. SecureVault generates a fresh `crypto.randomBytes(32)` key per file:

1. Upload → random 256-bit file key
2. File key encrypted with user's master key (AES-256-GCM) → stored as `encryptedFileKey` in DB
3. Master key never stored; derived per-session from password via PBKDF2

A compromised file key exposes exactly one file.

### 3.3 SHA-256 Integrity Hashing Paper [8]

Roslin Dayana & Shobha Rani [8] recommend computing Keccak/SHA-3 hashes of plaintext before encryption, stored separately from ciphertext. On download, the hash is re-verified.

**Implementation** (`backend/src/routes/files.ts`):

```
upload: SHA-256(plaintext) → integrityHash (DB)
download: decrypt → SHA-256(plaintext) → timingSafeEqual(actual, stored)
```

Mismatch triggers a 500 + security log entry. `timingSafeEqual` prevents timing attacks on hash comparison.

### 3.4 ECDH Key Exchange for File Sharing Paper [9]

Abualkas & B.D. [9] propose an ECC-AES hybrid where ECC handles key exchange and AES handles bulk data. SecureVault uses secp256k1 (Node.js native):

**Share flow**:

1. User A's ECDH private key decrypted with A's master key
2. Shared secret = ECDH(A_private, B_public)
3. AES key = HKDF(shared_secret)
4. File key re-encrypted with AES key → stored in `SharedFile.encryptedFileKey`

**Download (User B)**:

1. Same shared secret computed from B's private + A's public
2. Same HKDF derivation → same AES key → decrypt file key → decrypt file

The ECDH property ensures forward secrecy: knowing the shared secret for one pair does not reveal file keys for other pairs.

---

## 4. DevOps Security Container & CI/CD {#devops-security}

### 4.1 Hardened Container Images Paper [11]

Jarkas et al. [11] identify image-based attacks as the most common container threat. SecureVault addresses all three mitigation categories:

| Control             | Implementation                                                                |
| ------------------- | ----------------------------------------------------------------------------- |
| Minimal base images | `node:20-alpine`, `nginx:alpine`, `python:3.11-slim`                          |
| Multi-stage builds  | Dev tools / training data excluded from runtime images                        |
| Non-root users      | `USER app` / `USER nginx` in all Dockerfiles                                  |
| Read-only root FS   | `read_only: true` in docker-compose; writable paths via named volumes + tmpfs |
| `no-new-privileges` | `security_opt: [no-new-privileges:true]` on all services                      |

### 4.2 Network Isolation Paper [12]

Lee et al. [12] demonstrated ARP spoofing and privilege escalation attacks on the Docker default bridge network, which allows unrestricted container-to-container communication. SecureVault uses four custom networks:

```
frontend-net ──┐
               ├── frontend
backend-net  ──┤
               ├── backend
db-net (int) ──┤
               ├── db
ml-net (int) ──┘
               └── ml-service
```

- `db-net internal: true` DB has no external egress; not reachable from frontend
- `ml-net internal: true` ML service has no external egress; only backend can call it
- Frontend cannot resolve `db` or `ml-service` hostnames (verified in CI)

### 4.3 Trivy Vulnerability Scanning Paper [13]

Ugale & Potgantwar [13] used Trivy + XGBoost to classify images as high/low risk; images with HIGH/CRITICAL CVEs are blocked. SecureVault CI runs Trivy on every image build:

```bash
trivy image --severity HIGH,CRITICAL --exit-code 1 securevault-backend:ci
```

The pipeline fails if any HIGH or CRITICAL CVE is found. JSON reports are archived as CI artifacts for audit.

### 4.4 Secrets Scanning Paper [14]

Prates & Pereira [14] identify secrets scanning as a key under-adopted DevSecOps practice. SecureVault applies it at two points:

1. **Pre-commit hook** (`.pre-commit-config.yaml`): Gitleaks scans staged changes before every local commit.
2. **CI gate 1** (`.github/workflows/security-pipeline.yml`): Gitleaks scans the full commit history on every push/PR. No subsequent gates run if credentials are found.

Custom rules in `.gitleaks.toml` detect SecureVault-specific patterns (`MASTER_ENCRYPTION_KEY`, `JWT_SECRET`, PostgreSQL URLs with passwords).

### 4.5 Docker Secrets Paper [15]

Sinan et al. [15] identify inconsistent secret handling as a top DevSecOps challenge. Environment variables appear in `docker inspect`, container logs, and process lists. Docker Secrets mount credentials as read-only files at `/run/secrets/<name>`, invisible to the Docker API.

**Production secret flow**:

```bash
./scripts/init-secrets.sh        # generates ./secrets/{db_password,jwt_secret,master_key}.txt
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

`backend/src/config/secrets.ts` checks `/run/secrets/<name>` before falling back to environment variables (for dev). The `DATABASE_URL` password placeholder `__DB_PASSWORD__` is substituted at process startup from the secret file.

---

## 5. Running Security Scans Locally {#running-scans}

### Gitleaks (secrets scan)

```bash
# Install
brew install gitleaks              # macOS
# or: https://github.com/gitleaks/gitleaks/releases

# Scan all commits
gitleaks detect --source . --config .gitleaks.toml

# Scan staged files only (same as pre-commit hook)
gitleaks protect --staged --config .gitleaks.toml
```

### Trivy (container CVE scan)

```bash
# Install
brew install trivy                 # macOS
# or: https://github.com/aquasecurity/trivy/releases

# Build images first
docker compose build

# Scan each image
trivy image --severity HIGH,CRITICAL securityproj-backend:latest
trivy image --severity HIGH,CRITICAL securityproj-frontend:latest
trivy image --severity HIGH,CRITICAL securityproj-ml-service:latest

# Full JSON report
trivy image --format json -o trivy-report.json securityproj-backend:latest
```

### ESLint SAST

```bash
cd backend  && npm run lint
cd frontend && npm run lint
```

### npm audit (dependency CVEs)

```bash
cd backend  && npm audit --audit-level=high
cd frontend && npm audit --audit-level=high
```

### CSP nonce rotation test

```bash
docker compose up -d
N1=$(curl -sI http://localhost:3001/api/files -H "Authorization: Bearer x" | \
     grep -i content-security-policy | grep -o "nonce-[^']*")
N2=$(curl -sI http://localhost:3001/api/files -H "Authorization: Bearer x" | \
     grep -i content-security-policy | grep -o "nonce-[^']*")
[ "$N1" != "$N2" ] && echo "PASS" || echo "FAIL"
```

### Network isolation test

```bash
# Frontend must NOT be able to reach DB or ML service
docker exec securevault-frontend sh -c "wget -qO- --timeout=3 http://db:5432/ 2>&1 || echo BLOCKED"
docker exec securevault-frontend sh -c "wget -qO- --timeout=3 http://ml-service:8000/ 2>&1 || echo BLOCKED"

# Backend MUST reach ML service
docker exec securevault-backend wget -qO- http://ml-service:8000/health
```

---

## 6. Bibliography {#bibliography}

| #    | Authors                      | Title                                                                                       | Year |
| ---- | ---------------------------- | ------------------------------------------------------------------------------------------- | ---- |
| [1]  | Hannousse & Yahiouche        | Twenty-two years since revealing cross-site scripting attacks                               | 2024 |
| [2]  | Kaur, Raj & Lee              | Cross Channel Scripting and Code Injection Attacks on Web and Cloud-Based Applications      | 2022 |
| [3]  | Tadhani et al.               | Securing web applications against XSS and SQLi attacks using a novel deep learning approach | 2024 |
| [4]  | Li et al.                    | An LSTM based cross-site scripting attack detection scheme for Cloud Computing environments | 2023 |
| [5]  | Knittel et al.               | The Nonce-nce of Web Security: An Investigation of CSP Nonces Reuse                         | 2024 |
| [6]  | Shivaramakrishna & Nagaratna | A novel hybrid cryptographic framework                                                      | 2023 |
| [7]  | Backendal, Haller & Paterson | MEGA: Malleable Encryption Goes Awry                                                        | 2023 |
| [8]  | Roslin Dayana & Shobha Rani  | Secure cloud data storage solution with better data accessibility                           | 2023 |
| [9]  | Abualkas & B.D.              | Hybrid Approach to Cloud Storage Security Using ECC-AES Encryption                          | 2024 |
| [10] | Chen et al.                  | EStore: a User-Friendly Encrypted Storage Scheme                                            | 2023 |
| [11] | Jarkas et al.                | A Container Security Survey: Exploits, Attacks, and Defenses                                | 2025 |
| [12] | Lee et al.                   | Experimental Analysis of Security Attacks for Docker Container Communications               | 2023 |
| [13] | Ugale & Potgantwar           | Risk Classification of Docker Container Images Using Machine Learning                       | 2025 |
| [14] | Prates & Pereira             | DevSecOps Practices and Tools                                                               | 2024 |
| [15] | Sinan et al.                 | Integrating Security Controls in DevSecOps                                                  | 2025 |
