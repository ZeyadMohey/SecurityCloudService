/**
XSS scan middleware 
Runs after multer so req.file is populated.
Scans: req.file.originalname and string fields in req.body.
Rejects with 400 if ML confidence > 0.7.
Sets req.xssScanResult = null when ML service is unavailable 
*/

import type { NextFunction, Request, Response } from "express";
import { scanText, type ScanResult } from "../services/xss-scanner";

const XSS_THRESHOLD = 0.7;

/* Collects text candidates from the uploaded filename and body string fields.*/
function collectTexts(req: Request): string[] {
  const candidates: string[] = [];

  if (req.file?.originalname) {
    candidates.push(req.file.originalname);
  }

  for (const value of Object.values(req.body as Record<string, unknown>)) {
    if (typeof value === "string" && value.trim().length > 0) {
      candidates.push(value);
    }
  }

  return candidates;
}

export function xssScanMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  void (async () => {
    const texts = collectTexts(req);

    if (texts.length === 0) {
      req.xssScanResult = null;
      return next();
    }

    // Scan all candidates; reject if any exceeds threshold
    let worstResult: ScanResult | null = null;

    for (const text of texts) {
      const result = await scanText(text);

      if (result === null) {
        // ML unavailable — mark as null so upload route falls back to async scan
        req.xssScanResult = null;
        return next();
      }

      if (result.isXss && result.confidence > XSS_THRESHOLD) {
        res.status(400).json({
          error: "Content flagged as potential XSS",
          confidence: result.confidence,
        });
        return;
      }

      // Track worst (highest confidence) benign result
      if (worstResult === null || result.confidence > worstResult.confidence) {
        worstResult = result;
      }
    }

    req.xssScanResult = worstResult;
    next();
  })();
}
