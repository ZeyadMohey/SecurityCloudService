import { randomBytes } from 'crypto'
import type { Request, Response, NextFunction } from 'express'

/**
 * CSP Nonce Middlewar
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

  // Prevent caching of responses with nonce
  res.setHeader('Cache-Control', 'no-store')

  next()
}
