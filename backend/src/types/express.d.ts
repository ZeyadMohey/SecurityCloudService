import type { ScanResult } from '../services/xss-scanner'

/**
 * Extends Express's global Request interface so every route handler receives
 * userId and userEmail after the requireAuth middleware runs — no type casting needed.
 */
declare global {
  namespace Express {
    interface Request {
      userId: string
      userEmail: string
      /**
       * Set by xssScanMiddleware:
       *  - ScanResult  → ML returned a result (clean; XSS already rejected with 400)
       *  - null        → ML service was unavailable (graceful degrade)
       *  - undefined   → middleware not applied to this route
       */
      xssScanResult?: ScanResult | null
    }
  }
}

export {}
