import type { Request, Response, NextFunction } from 'express'
import jwt from 'jsonwebtoken'
import { config } from '../config/env'
import type { JwtPayload } from '../types'

/**
 * JWT authentication middleware.
 *
 * Reads the Bearer token from the Authorization header, verifies it with
 * JWT_SECRET, and attaches userId + userEmail to req (via types/express.d.ts).
 * Returns 401 — never 403 — so callers learn nothing about whether the resource
 * exists (avoids information leakage per Paper [1]).
 */
export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers['authorization']
  if (!authHeader?.startsWith('Bearer ')) {
    res.status(401).json({ message: 'Unauthorized' })
    return
  }

  const token = authHeader.slice(7)
  try {
    const payload = jwt.verify(token, config.jwtSecret) as JwtPayload
    req.userId = payload.userId
    req.userEmail = payload.email
    next()
  } catch {
    // jwt.verify throws on expired, invalid signature, malformed token — all 401
    res.status(401).json({ message: 'Unauthorized' })
  }
}
