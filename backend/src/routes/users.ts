/**
 * User routes — currently exposes only the share-autocomplete search endpoint.
 *
 * Mounted at /api/users in index.ts.
 */

import { Router } from 'express'
import type { Request, Response } from 'express'
import { PrismaClient } from '@prisma/client'
import { requireAuth } from '../middleware/auth'

const router = Router()
const prisma = new PrismaClient()

// ---------------------------------------------------------------------------
// GET /search  →  GET /api/users/search?email=...
// ---------------------------------------------------------------------------

/**
 * Partial-email user search for the share-file autocomplete.
 *
 * Security notes:
 *  - Requires authentication — unauthenticated callers cannot enumerate users.
 *  - Results exclude the requesting user (you cannot share with yourself).
 *  - Only id and email are returned — keys, password hashes, and all other
 *    sensitive fields are never exposed.
 *  - A minimum query length of 2 characters is enforced to limit bulk
 *    enumeration; results are capped at 5 to further reduce information leakage.
 */
router.get('/search', requireAuth, async (req: Request, res: Response): Promise<void> => {
  const query = typeof req.query['email'] === 'string' ? req.query['email'].trim() : ''

  if (query.length < 2) {
    res.status(400).json({ message: 'Search query must be at least 2 characters' })
    return
  }

  try {
    const users = await prisma.user.findMany({
      where: {
        email: { contains: query, mode: 'insensitive' },
        // Exclude the requesting user — they cannot share with themselves
        NOT: { id: req.userId },
      },
      select: { id: true, email: true },
      take: 5,
      orderBy: { email: 'asc' },
    })

    res.json(users)
  } catch {
    res.status(500).json({ message: 'User search failed' })
  }
})

export default router
