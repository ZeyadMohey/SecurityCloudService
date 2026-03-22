# Minimal python:3.11-slim — no training data, no raw dataset, no dev tooling.
# Paper [11]: attack surface reduction via minimal image.
# Paper [12]: only model inference code is present at runtime.
FROM python:3.11-slim AS runtime

# Paper [13] (Ugale & Potgantwar): apply all available OS patches at build time
# to remediate Debian base-image CVEs before Trivy scanning in CI.
RUN apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

# Non-root user — Paper [11] (container escape prevention)
RUN groupadd -r app && useradd -r -g app app

WORKDIR /app

# Upgrade pip and setuptools before installing requirements.
# setuptools vendors wheel and jaraco.context internally — upgrading to 82+
# pulls in wheel>=0.46.2 (fixes CVE-2026-24049) and drops jaraco.context<6
# (fixes CVE-2026-23949). Paper [13]: keep all package versions CVE-free.
RUN pip install --no-cache-dir --upgrade pip setuptools

# Install only production dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --timeout=300 -r requirements.txt

# Application code only — no training data
COPY --chown=app:app app/ ./app/

# Model weights from local pre-trained models — baked into the image so no volume needed
RUN mkdir -p models
COPY --chown=app:app models/ ./models/

# Paper [11]: drop to non-root
USER app

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

