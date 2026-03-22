/*
Synchronous XSS scanner service.
Calls the ML microservice POST /scan and returns the result.
Returns null on timeout or network error so callers can degrade gracefully.
*/

import { config } from "../config/env";

export interface ScanResult {
  isXss: boolean;
  confidence: number;
}

const TIMEOUT_MS = 5_000;

export async function scanText(text: string): Promise<ScanResult | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const res = await fetch(`${config.mlServiceUrl}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
      signal: controller.signal,
    });

    if (!res.ok) {
      console.warn(
        `[xss-scanner] ML service returned ${res.status} for text: "${text.slice(0, 60)}"`,
      );
      return null;
    }

    const data = (await res.json()) as { is_xss: boolean; confidence: number };
    const result: ScanResult = {
      isXss: data.is_xss,
      confidence: data.confidence,
    };

    console.log(
      `[xss-scanner] scan="${text.slice(0, 60)}" is_xss=${result.isXss} confidence=${result.confidence.toFixed(3)}`,
    );

    return result;
  } catch (err: unknown) {
    if (err instanceof Error && err.name === "AbortError") {
      console.warn(
        `[xss-scanner] scan timed out after ${TIMEOUT_MS}ms for: "${text.slice(0, 60)}"`,
      );
    } else {
      console.warn(`[xss-scanner] scan failed:`, err);
    }
    return null;
  } finally {
    clearTimeout(timer);
  }
}
