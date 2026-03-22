/**
 * File management routes — upload, list, download, delete.
 *
 * Security: X-Master-Key header (base64, 32-byte PBKDF2 key); per-file
 * AES-256-GCM keys (Paper [10]); SHA-256 integrity check on download (Paper [8]);
 * ECDH shared-secret key unwrapping for shared files (Paper [9]).
 */

import { Router } from 'express'
import type { Request, Response } from 'express'
import multer from 'multer'
import path from 'path'
import fs from 'fs'
import { randomBytes, createHash, timingSafeEqual } from 'crypto'
import { v4 as uuidv4 } from 'uuid'
import { PrismaClient } from '@prisma/client'
import { requireAuth } from '../middleware/auth'
import { config } from '../config/env'
import { aesDecrypt } from '../utils/crypto'
import { decryptSharedFileKey } from '../services/encryption'
import {
  parseMasterKey,
  gcmEncryptBuffer,
  gcmDecryptBuffer,
  decryptUserPrivateKey,
} from '../utils/routeHelpers'
import { triggerXssScan } from '../services/xssScan'
import { xssScanMiddleware } from '../middleware/xss-scan'
import { sanitizeFilename } from '../utils/sanitizer'
import type { EncryptedData } from '../types'

const router = Router()
const prisma = new PrismaClient()

// ── Multer — temp storage ────────────────────────────────────────────────────

const tmpDir = path.join(config.uploadDir, 'tmp')
fs.mkdirSync(tmpDir, { recursive: true })
fs.mkdirSync(config.uploadDir, { recursive: true })

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, tmpDir),
    filename: (_req, _file, cb) => cb(null, uuidv4()),
  }),
  limits: { fileSize: 50 * 1024 * 1024 },
})

// ── POST /api/files/upload ───────────────────────────────────────────────────

router.post(
  '/upload',
  requireAuth,
  upload.single('file'),
  xssScanMiddleware,
  async (req: Request, res: Response): Promise<void> => {
    const tempPath = req.file?.path
    const cleanupTemp = (): void => { if (tempPath) fs.unlink(tempPath, () => undefined) }

    if (!req.file || !tempPath) { res.status(400).json({ message: 'No file provided' }); return }

    const masterKey = parseMasterKey(req)
    if (!masterKey) {
      cleanupTemp()
      res.status(400).json({ message: 'X-Master-Key header required (base64-encoded 32-byte key)' })
      return
    }

    try {
      // Paper [1]: sanitize filename before storage
      const safeOriginalName = sanitizeFilename(req.file.originalname)

      const plaintext = fs.readFileSync(tempPath)
      const integrityHash = createHash('sha256').update(plaintext).digest('hex')
      const fileKey = randomBytes(32)
      const fileEnc = gcmEncryptBuffer(plaintext, fileKey)
      const keyEnc  = gcmEncryptBuffer(fileKey, masterKey)

      const fileId = uuidv4()
      fs.writeFileSync(path.join(config.uploadDir, `${fileId}.enc`), fileEnc.ciphertext)

      const encryptedFileKey = JSON.stringify({
        ciphertext: keyEnc.ciphertext.toString('hex'),
        iv: keyEnc.iv,
        authTag: keyEnc.authTag,
      } satisfies EncryptedData)

      // Derive scan status from synchronous middleware result
      // req.xssScanResult === null  → ML unavailable (will async-scan below)
      // req.xssScanResult === ScanResult → ML returned clean (XSS already rejected)
      const scanResult = req.xssScanResult
      const xssScanStatus = scanResult != null ? 'clean' : 'pending'
      const xssScanScore  = scanResult != null ? scanResult.confidence : null

      const file = await prisma.file.create({
        data: {
          id: fileId,
          originalName: safeOriginalName,
          storagePath: `${fileId}.enc`,
          mimeType: req.file.mimetype,
          size: req.file.size,
          encryptedFileKey,
          iv: fileEnc.iv,
          authTag: fileEnc.authTag,
          integrityHash,
          ownerId: req.userId,
          xssScanStatus,
          xssScanScore,
        },
      })

      cleanupTemp()

      // Only fire async fallback scan when ML was unavailable during upload
      if (scanResult === null || scanResult === undefined) {
        triggerXssScan(file.id, safeOriginalName)
      }

      res.status(201).json({
        id: file.id,
        originalName: file.originalName,
        mimeType: file.mimeType,
        size: file.size,
        createdAt: file.createdAt,
        xssScanStatus: file.xssScanStatus,
      })
    } catch (err) {
      cleanupTemp()
      console.error('[upload]', err instanceof Error ? err.message : String(err))
      res.status(500).json({ message: 'Upload failed' })
    }
  }
)

// ── GET /api/files ───────────────────────────────────────────────────────────

router.get('/', requireAuth, async (req: Request, res: Response): Promise<void> => {
  try {
    const [owned, shared] = await Promise.all([
      prisma.file.findMany({
        where: { ownerId: req.userId },
        select: { id: true, originalName: true, mimeType: true, size: true, xssScanStatus: true, createdAt: true },
        orderBy: { createdAt: 'desc' },
      }),
      prisma.sharedFile.findMany({
        where: { sharedWithId: req.userId },
        include: {
          file: { select: { id: true, originalName: true, mimeType: true, size: true, xssScanStatus: true, createdAt: true } },
          sharedBy: { select: { email: true } },
        },
        orderBy: { createdAt: 'desc' },
      }),
    ])

    res.json({
      owned,
      shared: shared.map((s) => ({ shareId: s.id, permission: s.permission, sharedBy: s.sharedBy.email, ...s.file })),
    })
  } catch {
    res.status(500).json({ message: 'Failed to fetch files' })
  }
})

// ── GET /api/files/:id/download ──────────────────────────────────────────────

router.get('/:id/download', requireAuth, async (req: Request, res: Response): Promise<void> => {
  const masterKey = parseMasterKey(req)
  if (!masterKey) {
    res.status(400).json({ message: 'X-Master-Key header required (base64-encoded 32-byte key)' })
    return
  }

  const fileId = req.params['id']

  try {
    const file = await prisma.file.findUnique({ where: { id: fileId } })
    if (!file) { res.status(404).json({ message: 'File not found' }); return }

    let fileKey: Buffer

    if (file.ownerId === req.userId) {
      fileKey = aesDecrypt(JSON.parse(file.encryptedFileKey) as EncryptedData, masterKey)
    } else {
      const sharedRecord = await prisma.sharedFile.findUnique({
        where: { fileId_sharedWithId: { fileId, sharedWithId: req.userId } },
        include: { sharedBy: { select: { ecdhPublicKey: true } } },
      })
      if (!sharedRecord) { res.status(403).json({ message: 'Access denied' }); return }

      const recipient = await prisma.user.findUnique({
        where: { id: req.userId }, select: { ecdhPrivateKeyEnc: true },
      })
      if (!recipient) { res.status(500).json({ message: 'Download failed' }); return }

      const recipientPrivKey = decryptUserPrivateKey(recipient.ecdhPrivateKeyEnc, masterKey)
      const senderPubKey     = Buffer.from(sharedRecord.sharedBy.ecdhPublicKey, 'hex')
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
      fileKey = decryptSharedFileKey(JSON.parse(sharedRecord.encryptedFileKey), recipientPrivKey, senderPubKey)
    }

    const encFilePath = path.join(config.uploadDir, file.storagePath)
    if (!fs.existsSync(encFilePath)) {
      console.error(`[download] missing on disk: ${encFilePath}`)
      res.status(500).json({ message: 'Download failed' })
      return
    }

    const plaintext  = gcmDecryptBuffer(fs.readFileSync(encFilePath), fileKey, file.iv, file.authTag)
    const actualHash = createHash('sha256').update(plaintext).digest('hex')

    if (
      actualHash.length !== file.integrityHash.length ||
      !timingSafeEqual(Buffer.from(actualHash, 'hex'), Buffer.from(file.integrityHash, 'hex'))
    ) {
      console.error(`[integrity] file=${fileId} hash mismatch`)
      res.status(500).json({ message: 'File integrity check failed' })
      return
    }

    const safeFilename = path.basename(file.originalName).replace(/["\\]/g, '')
    res.setHeader('Content-Type', file.mimeType || 'application/octet-stream')
    res.setHeader('Content-Disposition', `attachment; filename="${safeFilename}"`)
    res.setHeader('Content-Length', String(plaintext.length))
    res.send(plaintext)
  } catch (err) {
    console.error('[download]', err instanceof Error ? err.message : String(err))
    res.status(500).json({ message: 'Download failed' })
  }
})

// ── DELETE /api/files/:id ────────────────────────────────────────────────────

router.delete('/:id', requireAuth, async (req: Request, res: Response): Promise<void> => {
  const fileId = req.params['id']

  try {
    const file = await prisma.file.findFirst({ where: { id: fileId, ownerId: req.userId } })
    if (!file) { res.status(404).json({ message: 'File not found' }); return }

    await prisma.$transaction([
      prisma.sharedFile.deleteMany({ where: { fileId: file.id } }),
      prisma.file.delete({ where: { id: file.id } }),
    ])

    const encFilePath = path.join(config.uploadDir, file.storagePath)
    fs.unlink(encFilePath, (err) => {
      if (err && err.code !== 'ENOENT') console.error(`[delete] disk cleanup: ${err.message}`)
    })

    res.status(204).send()
  } catch {
    res.status(500).json({ message: 'Failed to delete file' })
  }
})

export default router
