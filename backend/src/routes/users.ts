import { Router } from 'express'
import type { Request, Response } from 'express'
import { PrismaClient } from '@prisma/client'
import { requireAuth } from '../middleware/auth'

const router = Router()
const prisma = new PrismaClient()

// SEARCH USERS

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
        // Exclude the requesting user
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
