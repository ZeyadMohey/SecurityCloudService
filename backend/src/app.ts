/**
 * Express application factory — imported by tests and by index.ts (server entry).
 * Keeping this separate from server startup allows supertest to import the app
 * without binding a port.
 */

import express from 'express'
import type { Request, Response, NextFunction } from 'express'
import helmet from 'helmet'
import cors from 'cors'
import rateLimit from 'express-rate-limit'
import { PrismaClient } from '@prisma/client'
import { config } from './config/env'
import { cspNonce } from './middleware/cspNonce'
import authRouter from './routes/auth'
import filesRouter from './routes/files'
import shareRouter from './routes/share'
import usersRouter from './routes/users'

// Shared Prisma instance used only by the /health check
const healthPrisma = new PrismaClient()

const app = express()

// Security headers — helmet sets X-Frame-Options, X-Content-Type-Options,
// Strict-Transport-Security, X-Download-Options, etc.
// CSP is managed by our per-request nonce middleware instead of helmet's static CSP.
app.use(helmet({ contentSecurityPolicy: false }))

// CORS — restrict to known frontend origin to block cross-origin requests
app.use(
  cors({
    origin:
      config.nodeEnv === 'production'
        ? 'https://securevault.app'
        : 'http://localhost:5173',
    credentials: true,
  })
)

// Per-request CSP nonce — Paper [5] (Knittel et al.)
app.use(cspNonce)

// Body parsing — 10 MB limit
app.use(express.json({ limit: '10mb' }))
app.use(express.urlencoded({ extended: true, limit: '10mb' }))

// Rate limiters — skipped in test mode to avoid inter-test interference
const isTest = config.nodeEnv === 'test'

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  skip: () => isTest,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many requests, please try again later.' },
})
app.use(globalLimiter)

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  skip: () => isTest,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many authentication attempts, please try again later.' },
})

app.use('/api/auth', authLimiter, authRouter)
app.use('/api/files', filesRouter)
app.use('/api/files', shareRouter)
app.use('/api/users', usersRouter)

// Health check — reports DB + ML service connectivity (Papers [13], [15])
app.get('/health', (_req: Request, res: Response) => {
  void (async () => {
    // DB check
    let dbStatus: 'ok' | 'error' = 'ok'
    try {
      await healthPrisma.$queryRaw`SELECT 1`
    } catch {
      dbStatus = 'error'
    }

    // ML service check with 3 s timeout
    let mlStatus: 'ok' | 'degraded' = 'ok'
    const controller = new AbortController()
    const mlTimer = setTimeout(() => controller.abort(), 3_000)
    try {
      const mlRes = await fetch(`${config.mlServiceUrl}/health`, { signal: controller.signal })
      if (!mlRes.ok) mlStatus = 'degraded'
    } catch {
      mlStatus = 'degraded'
    } finally {
      clearTimeout(mlTimer)
    }

    const overall = dbStatus === 'error' ? 'error' : mlStatus === 'ok' ? 'ok' : 'degraded'
    res.status(dbStatus === 'error' ? 503 : 200).json({
      status: overall,
      timestamp: new Date().toISOString(),
      version: '1.0.0',
      services: {
        database: { status: dbStatus },
        mlService: { status: mlStatus },
      },
    })
  })()
})

// 404 handler
app.use((_req: Request, res: Response) => {
  res.status(404).json({ message: 'Not found' })
})

// Global error handler — never leaks internal details
app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  const message = err instanceof Error ? err.message : String(err)
  console.error('[Unhandled error]', message)
  res.status(500).json({ message: 'An unexpected error occurred' })
})

export default app
