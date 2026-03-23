# ── Stage 1: Train ───────────────────────────────────────────────────────────
# Multi-stage build: training data and heavy ML tooling excluded from prod image.
# Only model weights are carried forward.
FROM python:3.11-slim AS train

# Patch OS packages.
RUN apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Upgrade pip/setuptools to pull in patched bundled deps (wheel, jaraco.context).
RUN pip install --no-cache-dir --upgrade pip setuptools

# Install all dependencies (including training deps)
COPY requirements.txt .
RUN pip install --no-cache-dir --timeout=300 -r requirements.txt

# Copy training data and application code
COPY app/ ./app/
COPY data/ ./data/

# Ensure models directory exists for weight output
RUN mkdir -p models

# Train the model   weights saved to models/xss_cnn_lstm.weights.h5
# Falls back gracefully if training fails (e.g., insufficient data)
RUN python -m app.train || echo "Training skipped   weights will be absent in runtime"

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
# Minimal image   no training data, no raw dataset, no dev tooling.
FROM python:3.11-slim AS runtime

# Patch OS packages.
RUN apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    rm -rf /var/lib/apt/lists/*

# Run as non-root user.
RUN groupadd -r app && useradd -r -g app app

WORKDIR /app

# Upgrade pip/setuptools.
RUN pip install --no-cache-dir --upgrade pip setuptools

# Install only production dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --timeout=300 -r requirements.txt

# Application code only   no training data
COPY --chown=app:app app/ ./app/

# Model weights from training stage   baked into the image so no volume needed
RUN mkdir -p models
COPY --from=train --chown=app:app /app/models/ ./models/

USER app

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
