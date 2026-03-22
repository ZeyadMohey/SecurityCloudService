import { randomBytes } from 'crypto'
import type { Request, Response, NextFunction } from 'express'

/**
 * CSP Nonce Middleware — Paper 5 (Knittel et al.)
 *
 * Generates a cryptographically unique nonce per request.
 * NEVER reuses nonces across requests (addresses Paper 5's nonce reuse vulnerability).
 * Sets Cache-Control: no-store to prevent CDN/proxy caching of nonce-bearing responses.
 */
export function cspNonce(_req: Request, res: Response, next: NextFunction): void {
  const nonce = randomBytes(16).toString('base64')
  res.locals['cspNonce'] = nonce

  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      `script-src 'nonce-${nonce}'`,
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data:",
      "connect-src 'self'",
      "frame-ancestors 'none'",
      "object-src 'none'",
      "base-uri 'self'",
    ].join('; ')
  )

  // Prevent caching of responses with nonces — CDN caching a nonce is a security hole
  res.setHeader('Cache-Control', 'no-store')

  next()
}
