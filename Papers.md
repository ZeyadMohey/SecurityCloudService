# CONTEXT BLOCK Research Paper Implementation Guide

This file provides Claude Code with the specific knowledge from each of the 15 research papers referenced in the Security Report, so that implementations are grounded in actual academic work rather than generic security patterns.

---

## FRONTEND PAPERS XSS Prevention & Detection

### Paper [1]: Hannousse & Yahiouche "Twenty-two years since revealing cross-site scripting attacks" (2024)

**Key findings to implement:**

- 84.71% of existing work targets only reflected/stored XSS. Our system must also handle DOM-based XSS (via shared link URL parameters) and mutation-based XSS.
- Only 1.48% of studies include automatic XSS fixing. We implement auto-sanitization (DOMPurify + server-side encoding) as a fix mechanism, not just detection.
- Most detection works on a single-page basis. Our scanner must consider cross-page attack vectors a malicious filename uploaded by User A could trigger XSS when User B views the shared files page.
  **Implementation mapping:** Layered defense strategy sanitize at input, encode at output, scan with ML, sandbox at render.

### Paper [2]: Kaur, Raj & Lee "Cross Channel Scripting and Code Injection Attacks on Web and Cloud-Based Applications" (2022)

**Key findings to implement:**

- Cloud environments amplify XSS risk due to shared infrastructure, distributed architecture, and multi-tenant systems.
- Recommends: input validation → output encoding → CSP headers, applied as a layered defense.
- Attack classification before handling different XSS types need different mitigations.
  **Implementation mapping:**
- Classify input type before sanitizing (filename vs URL param vs metadata each has different dangerous character sets)
- CSP headers with strict nonce policy
- File previews in sandboxed iframes (cloud-specific: prevents shared workspace cross-contamination)

### Paper [3]: Tadhani et al. "Securing web applications against XSS and SQLi attacks using a novel deep learning approach" (2024)

**Key findings to implement:**

- CNN-LSTM hybrid model: CNN extracts local pattern features from tokenized HTTP request payloads, LSTM captures sequential patterns across attack inputs.
- Trained on HTTP CSIC 2010 dataset + supplementary data.
- High accuracy with low false positive rates.
  **Implementation mapping:**
- Our FastAPI ML service uses a CNN-LSTM architecture
- Input: tokenized string (filename, metadata text)
- CNN layers extract character/token n-gram features
- LSTM layer models sequence patterns common in XSS payloads
- Output: binary classification (benign/malicious) + confidence score

### Paper [4]: Li et al. "An LSTM based cross-site scripting attack detection scheme for Cloud Computing environments" (2023)

**Key findings to implement:**

- Character-level Bi-directional LSTM with multi-attention mechanism (CMABLSTM)
- Character-level approach learns directly from raw character sequences no manual feature engineering
- Multi-attention focuses on discriminative parts of inputs (e.g., `<script>`, `onerror=`, `javascript:`)
- Specifically designed for cloud computing environments
- Outperforms traditional pattern-based methods on cloud-specific test sets
  **Implementation mapping:**
- Use character-level tokenization (char → integer mapping, max sequence length ~200)
- The model should be trained to recognize patterns like: `<script`, `javascript:`, `onerror`, `onload`, `eval(`, `document.cookie`, `<img src=x`, `<svg/onload`, URL-encoded variants (`%3Cscript`), and Unicode obfuscation
- For training, use Kaggle XSS dataset (syedsaqlainhussain/cross-site-scripting-xss-dataset-for-deep-learning) which has ~20,000+ labeled samples
- Alternative dataset: fawaz2015/XSS-dataset on GitHub (138,569 samples with 66 pre-processed features)

### Paper [5]: Knittel et al. "The Nonce-nce of Web Security: An Investigation of CSP Nonces Reuse" (2024)

**Key findings to implement:**

- Many production websites reuse CSP nonces across page loads this completely nullifies CSP protection
- Nonce reuse happens due to: server-side caching, CDN caching, load balancer session stickiness, and developer misunderstanding
- Fix: generate a new cryptographic nonce for EVERY HTTP response, never cache responses that contain nonces
  **Implementation mapping:**
- Express middleware generates `crypto.randomBytes(16).toString('base64')` per request
- CSP header: `script-src 'nonce-${nonce}'` no `'unsafe-inline'`, no `'unsafe-eval'`
- Set `Cache-Control: no-store` on HTML responses to prevent CDN nonce caching
- Nonce passed to React via a `<meta>` tag or inline `<script nonce="${nonce}">` for hydration
- Rate limit nonce generation to prevent nonce-harvesting attacks

---

## BACKEND PAPERS Data Encryption

### Paper [6]: Shivaramakrishna & Nagaratna "A novel hybrid cryptographic framework" (2023)

**Key findings to implement:**

- Hybrid AES-OTP + RSA framework with three components:
  1. Adaptive key management (auto key creation, distribution, rotation)
  2. Dual-layer encryption: symmetric AES for fast file encryption + asymmetric for key distribution
  3. Time-limited access control for shared resources
     **Implementation mapping:**
- Our system uses AES-256-GCM (symmetric) for file encryption + ECC (asymmetric) for key exchange same dual-layer principle
- Implement key rotation: file keys are never reused, and user master keys can be rotated (re-encrypt all file keys with new master key)
- Time-limited sharing: SharedFile records can have an `expiresAt` field, enforced at download time

### Paper [7]: Backendal, Haller & Paterson "MEGA: Malleable Encryption Goes Awry" (2023)

**Key findings what NOT to do:**

- MEGA used AES-ECB mode for encrypting RSA private keys
- ECB mode encrypts identical plaintext blocks to identical ciphertext blocks leaks patterns
- RSA key was reused across operations
- Attack: malicious server observing ~512 login sessions could recover user's RSA private key
- Root cause: misuse of AES mode + key reuse
  **Implementation mapping we AVOID these mistakes:**
- NEVER use AES-ECB. Always AES-256-GCM (authenticated encryption with random IVs)
- NEVER reuse IVs. Generate `crypto.randomBytes(12)` (96-bit) per encryption operation
- NEVER reuse keys across different operations. Per-file keys, derived per-operation
- Store and verify GCM auth tags detects tampering that ECB cannot
- User's ECDH private key encrypted with password-derived key using AES-256-GCM (not ECB)

### Paper [8]: Roslin Dayana & Shobha Rani "Secure cloud data storage solution with better data accessibility" (2023)

**Key findings to implement:**

- Dual-layer approach: Keccak hashing (SHA-3 family) for integrity verification + AES for encryption
- Integrity verification happens BEFORE data leaves the source don't rely on third-party verification
- SHA3-256 provides competitive speed with high integrity assurance
- Hash computed on plaintext, stored separately from ciphertext
  **Implementation mapping:**
- Compute SHA-256 hash of file plaintext BEFORE encryption, store in DB as `integrityHash`
- On download: decrypt → hash → compare with stored hash
- If mismatch: reject file, log security event, notify user
- We use SHA-256 (available natively in Node.js crypto) SHA-3 would be ideal per the paper but SHA-256 is sufficient for this implementation and universally available

### Paper [9]: Abualkas & B.D. "Hybrid Approach to Cloud Storage Security Using ECC-AES Encryption" (2024)

**Key findings to implement:**

- ECC for key generation and exchange smaller key sizes than RSA with equivalent security
- AES for actual file encryption
- ECC-AES hybrid: ECC handles key exchange, AES handles bulk data encryption
- Standard practice in modern cryptography
  **Implementation mapping:**
- Use Node.js `crypto.createECDH('secp256k1')` for key pair generation
- On user registration: generate ECDH key pair, store public key in DB, encrypt private key with password-derived key
- For sharing: ECDH shared secret derived from sender's private key + recipient's public key
- Shared secret → HKDF → AES-256 key → encrypt file key for recipient
- secp256k1 chosen for its widespread use (same curve as Bitcoin) and Node.js native support

### Paper [10]: Chen et al. "EStore: a User-Friendly Encrypted Storage Scheme" (2023)

**Key findings to implement:**

- Three problems solved: (1) plaintext data loss of control after upload, (2) reduced availability after encryption, (3) single key for multiple files increases breach damage
- Solutions: per-file encryption keys, searchable encryption, authentication framework for key management
- Per-file keys: each file has its own AES key compromising one key affects only one file
- Feasible with minimal overhead in testing
  **Implementation mapping:**
- Every file upload generates a new `crypto.randomBytes(32)` as the file-specific AES key
- File key encrypted with user's master key (derived from password via PBKDF2)
- File key NEVER stored in plaintext anywhere
- For searchable encryption: we implement filename search on server-side encrypted metadata (filenames stored encrypted with a deterministic encryption scheme for search, separate from the file content encryption)
- Note: full searchable encryption (as in the paper) is complex. We implement a simplified version where filenames are stored in plaintext in DB (since they've been XSS-scanned) but file contents are always encrypted

---

## DEVOPS PAPERS Container Security & CI/CD

### Paper [11]: Jarkas et al. "A Container Security Survey: Exploits, Attacks, and Defenses" (2025)

**Key findings to implement:**

- Four main container attack types: (1) container escape, (2) network-based attacks, (3) image-based attacks, (4) orchestration attacks
- Image-based attacks are the most common focus on automated image scanning
- Container escape prevention: non-root users, minimal base images, seccomp profiles
  **Implementation mapping:**
- Dockerfiles: `FROM node:20-alpine`, `RUN addgroup -S app && adduser -S app -G app`, `USER app`
- Only install production dependencies in images
- Use multi-stage builds to exclude dev tools from production images
- Apply `security_opt: ["no-new-privileges:true"]` in docker-compose

### Paper [12]: Lee et al. "Experimental Analysis of Security Attacks for Docker Container Communications" (2023)

**Key findings to implement:**

- Default Docker networking is insecure demonstrated via ARP spoofing, DDoS, privilege escalation
- Default bridge network allows all containers to communicate freely
- Runtime network isolation is rarely enforced in practice
  **Implementation mapping:**
- Create custom Docker networks: `frontend-net`, `backend-net`, `db-net`
- Frontend container only on `frontend-net` + `backend-net`
- Backend container on `backend-net` + `db-net` + `ml-net`
- Database container ONLY on `db-net` not reachable from frontend
- ML service ONLY on `ml-net` only reachable from backend
- Set `internal: true` on `db-net` and `ml-net` to prevent external access

### Paper [13]: Ugale & Potgantwar "Risk Classification of Docker Container Images Using Machine Learning" (2025)

**Key findings to implement:**

- Used Trivy (open-source vulnerability scanner) to scan Docker images
- Features extracted: vulnerability score, package density metric
- XGBoost classifier achieved 100% accuracy in categorizing images as high/low risk
- Pipeline: scan → extract features → classify risk → block high-risk deployments
  **Implementation mapping:**
- GitHub Actions CI step: `trivy image --severity HIGH,CRITICAL --exit-code 1 securevault-backend:latest`
- Fail the pipeline if HIGH or CRITICAL CVEs found
- Generate JSON report: `trivy image --format json -o trivy-report.json`
- Block merge on failure no high-risk images reach production

### Paper [14]: Prates & Pereira "DevSecOps Practices and Tools" (2024)

**Key findings to implement:**

- 39 DevSecOps practices identified across pipeline stages
- Key practices: SAST, DAST, SCA, secrets scanning, container scanning
- Practices linked to specific pipeline stages and tools
- Many practices still under-adopted despite proven effectiveness
  **Implementation mapping:**
- Pipeline stages (sequential security gates):
  1. **Pre-commit**: Gitleaks for secrets detection
  2. **Build**: Docker build with linting
  3. **SAST**: ESLint security plugin for static analysis
  4. **Container scan**: Trivy image scanning
  5. **Secrets scan**: Gitleaks on full repo
  6. **Deploy**: Only if all gates pass
- Install Gitleaks as pre-commit hook: `.pre-commit-config.yaml`

### Paper [15]: Sinan et al. "Integrating Security Controls in DevSecOps" (2025)

**Key findings to implement:**

- 19 challenges and 18 solutions for integrating security into CI/CD
- Key challenges: lack of automated security feedback, inconsistent secret handling, tool integration complexity
- Solutions: automated security testing at every stage, infrastructure as code, continuous monitoring
  **Implementation mapping:**
- Docker Secrets for all credentials:
  ```yaml
  secrets:
    db_password:
      file: ./secrets/db_password.txt
    jwt_secret:
      file: ./secrets/jwt_secret.txt
    master_key:
      file: ./secrets/master_key.txt
  ```
- Read secrets in Node.js from `/run/secrets/<name>` (Docker mounts them as files)
- Never use environment variables for secrets in production
- Health check endpoints for continuous monitoring: `/health` on each service
