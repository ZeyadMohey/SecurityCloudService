"""
FastAPI entry point for the XSS detection microservice.

Endpoints:
  POST /scan  — scan text (filename/metadata) for XSS payloads
  GET  /health — service health check
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from pydantic import BaseModel

from .model import detector


# ---------------------------------------------------------------------------
# Lifespan: load model on startup
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    detector.load()
    if detector.is_loaded:
        print("XSS detection model loaded successfully")
    else:
        print("WARNING: model weights not found — /scan will return safe defaults")
    yield


app = FastAPI(
    title="SecureVault XSS Scanner",
    description="CNN-LSTM XSS detection microservice — Papers [3] & [4]",
    version="1.0.0",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    text: str


class ScanResponse(BaseModel):
    is_xss: bool
    confidence: float
    details: str


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post("/scan", response_model=ScanResponse)
async def scan(req: ScanRequest) -> ScanResponse:
    """Scan a text string (filename, description, metadata) for XSS content."""
    result = detector.predict(req.text)
    return ScanResponse(**result)


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Health check — reports whether the ML model is loaded."""
    return HealthResponse(status="ok", model_loaded=detector.is_loaded)
