"""
FastAPI entry point for the XSS detection microservice.
Endpoints:
  POST /scan : scan text (filename/metadata) for XSS payloads
  GET  /health : service health check
"""

from __future__ import annotations
import re
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, field_validator
from .model import detector

# Rule-based pre-filter — catches common XSS patterns regardless of length.
# This is a defense-in-depth layer to lower ML usage
_XSS_RULE = re.compile(
    r"<\s*script"               # <script ...>
    r"|javascript\s*:"          # javascript: URI
    r"|on\w+\s*="              # inline event handlers (onclick=, onerror=, …)
    r"|<\s*iframe"              # <iframe>
    r"|<\s*object"              # <object>
    r"|<\s*embed"               # <embed>
    r"|<\s*svg[^>]*on\w+\s*="  # SVG with event handlers
    r"|expression\s*\("         # CSS expression()
    r"|vbscript\s*:",           # vbscript: URI
    re.IGNORECASE,
)

# Hard cap: prevents DoS through excessively long payloads
_MAX_INPUT_CHARS = 50_000

# Lifespan: load model on startup
@asynccontextmanager
async def lifespan(app: FastAPI):
    detector.load()
    if detector.is_loaded:
        print("XSS detection model loaded successfully")
    else:
        print("WARNING: model weights not found, /scan will return safe defaults")
    yield


app = FastAPI(
    title="SecureVault XSS Scanner",
    description="CNN-LSTM XSS detection microservice — Papers [3] & [4]",
    version="1.0.0",
    lifespan=lifespan,
)


# Request / Response schemas
class ScanRequest(BaseModel):
    text: str

    @field_validator("text")
    @classmethod
    def enforce_max_length(cls, v: str) -> str:
        if len(v) > _MAX_INPUT_CHARS:
            raise ValueError(f"Input exceeds maximum allowed length of {_MAX_INPUT_CHARS} characters")
        return v

class ScanResponse(BaseModel):
    is_xss: bool
    confidence: float
    details: str

class HealthResponse(BaseModel):
    status: str
    model_loaded: bool


# Endpoints
@app.post("/scan", response_model=ScanResponse)
async def scan(req: ScanRequest) -> ScanResponse:
    """Scan a text string (filename, description, metadata) for XSS content.

    Detection is layered:
    1. Rule-based regex, instant, no length limit, catches known patterns.
    2. CNN-LSTM model with sliding-window, catches obfuscated/novel payloads
       even when they are hidden after benign padding beyond 200 characters.
    """
    # Layer 1: fast rule-based check (no length constraint)
    if _XSS_RULE.search(req.text):
        return ScanResponse(
            is_xss=True,
            confidence=1.0,
            details="XSS pattern matched by rule-based filter",
        )

    # Layer 2: ML model with sliding-window over the full input
    result = detector.predict(req.text)
    return ScanResponse(**result)


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Health check reports whether the ML model is loaded."""
    return HealthResponse(status="ok", model_loaded=detector.is_loaded)
