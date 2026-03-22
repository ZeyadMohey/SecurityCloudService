/**
 * Sharing routes — ECDH-based file key re-encryption (Paper [9])
 *
 * All routes are mounted under /api/files in index.ts, giving:
 *   POST   /api/files/:id/share
 *   GET    /api/files/shared-with-me
 *   DELETE /api/files/:id/share/:shareId
 *
 * ## Security design (Paper [9] — Abualkas & B.D., ECC-AES hybrid)
 *
 * Sharing a file never exposes the sender's master key or the recipient's
 * private key. Instead:
 *
 * 1. Sender decrypts their own ECDH private key (using their master key from
 *    the X-Master-Key header) and decrypts the per-file AES key.
 * 2. ECDH(sender_private, recipient_public) produces a shared secret that
 *    only those two parties can independently reproduce — the secret itself
 *    is never transmitted or stored.
 * 3. HKDF(SHA-256, shared_secret, random_salt) stretches the raw ECDH output
 *    into a proper 256-bit AES key.
 * 4. The file key is re-encrypted with that AES key and stored as a
 *    SharedKeyBundle JSON in SharedFile.encryptedFileKey.
 * 5. On download, the recipient performs the mirror operation using their
 *    own private key and the sender's public key (ECDH commutativity).
 */

import { Router } from 'express'
import type { Request, Response } from 'express'
import { PrismaClient } from '@prisma/client'
import { requireAuth } from '../middleware/auth'
import { aesDecrypt } from '../utils/crypto'
import { encryptFileKeyForSharing } from '../services/encryption'
import { parseMasterKey, decryptUserPrivateKey } from '../utils/routeHelpers'
import type { EncryptedData } from '../types'

const router = Router()
const prisma = new PrismaClient()

// ---------------------------------------------------------------------------
// POST /:id/share  →  POST /api/files/:id/share
// ---------------------------------------------------------------------------

router.post(
  '/:id/share',
  requireAuth,
  async (req: Request, res: Response): Promise<void> => {
    const masterKey = parseMasterKey(req)
    if (!masterKey) {
      res.status(400).json({ message: 'X-Master-Key header required (base64-encoded 32-byte key)' })
      return
    }

    const fileId = req.params['id']
    const body = req.body as { email?: unknown; permission?: unknown }

    // Validate request body
    if (typeof body.email !== 'string' || !body.email.trim()) {
      res.status(400).json({ message: 'email is required' })
      return
    }

    const recipientEmail = body.email.trim().toLowerCase()

    if (body.permission !== 'view' && body.permission !== 'download') {
      res.status(400).json({ message: 'permission must be "view" or "download"' })
      return
    }

    const permission = body.permission

    try {
      // Verify the authenticated user owns the file and fetch their ECDH key
      const file = await prisma.file.findFirst({
        where: { id: fileId, ownerId: req.userId },
        include: {
          owner: {
            select: {
              ecdhPrivateKeyEnc: true,
            },
          },
        },
      })

      if (!file) {
        res.status(404).json({ message: 'File not found' })
        return
      }

      // Prevent sharing with yourself
      const sender = await prisma.user.findUnique({
        where: { id: req.userId },
        select: { email: true },
      })

      if (sender?.email === recipientEmail) {
        res.status(400).json({ message: 'Cannot share a file with yourself' })
        return
      }

      // Look up recipient by email
      const recipient = await prisma.user.findUnique({
        where: { email: recipientEmail },
        select: { id: true, email: true, ecdhPublicKey: true },
      })

      if (!recipient) {
        res.status(404).json({ message: 'Recipient user not found' })
        return
      }

      // Check for duplicate share — the DB has a @@unique([fileId, sharedWithId])
      // constraint so this would fail at the DB level too, but we return a
      // friendlier message here.
      const existing = await prisma.sharedFile.findUnique({
        where: {
          fileId_sharedWithId: { fileId, sharedWithId: recipient.id },
        },
      })

      if (existing) {
        res.status(409).json({ message: 'File is already shared with this user' })
        return
      }

      // ── ECDH key re-encryption (Paper [9]) ─────────────────────────────────

      // Step 1: decrypt sender's ECDH private key using their master key
      const senderPrivKey = decryptUserPrivateKey(file.owner.ecdhPrivateKeyEnc, masterKey)

      // Step 2: decrypt the per-file AES key using sender's master key
      // encryptedFileKey is JSON { ciphertext, iv, authTag } (all hex)
      const keyBundle = JSON.parse(file.encryptedFileKey) as EncryptedData
      const fileKey = aesDecrypt(keyBundle, masterKey)

      // Step 3: re-encrypt file key for recipient via ECDH shared secret
      // ECDH(A_private, B_public) → HKDF → AES-256-GCM wrap of file key
      const recipientPubKey = Buffer.from(recipient.ecdhPublicKey, 'hex')
      const sharedBundle = encryptFileKeyForSharing(fileKey, senderPrivKey, recipientPubKey)

      // Step 4: persist the SharedFile record
      // SharedKeyBundle JSON goes in encryptedFileKey; iv also stored in its own
      // column because the schema was designed that way.
      const sharedFile = await prisma.sharedFile.create({
        data: {
          fileId,
          sharedById: req.userId,
          sharedWithId: recipient.id,
          encryptedFileKey: JSON.stringify(sharedBundle),
          iv: sharedBundle.iv,
          permission,
        },
      })

      res.status(201).json({
        sharedWith: recipient.email,
        permission: sharedFile.permission,
        createdAt: sharedFile.createdAt,
      })
    } catch (err) {
      console.error('[share]', err instanceof Error ? err.message : String(err))
      res.status(500).json({ message: 'Share failed' })
    }
  }
)

// ---------------------------------------------------------------------------
// GET /shared-with-me  →  GET /api/files/shared-with-me
// ---------------------------------------------------------------------------

router.get(
  '/shared-with-me',
  requireAuth,
  async (req: Request, res: Response): Promise<void> => {
    try {
      const shared = await prisma.sharedFile.findMany({
        where: { sharedWithId: req.userId },
        include: {
          file: {
            select: {
              id: true,
              originalName: true,
              mimeType: true,
              size: true,
              xssScanStatus: true,
              createdAt: true,
              owner: { select: { email: true } },
            },
          },
          sharedBy: { select: { email: true } },
        },
        orderBy: { createdAt: 'desc' },
      })

      res.json(
        shared.map((s) => ({
          shareId: s.id,
          permission: s.permission,
          sharedBy: s.sharedBy.email,
          fileOwner: s.file.owner.email,
          sharedAt: s.createdAt,
          file: {
            id: s.file.id,
            originalName: s.file.originalName,
            mimeType: s.file.mimeType,
            size: s.file.size,
            xssScanStatus: s.file.xssScanStatus,
            createdAt: s.file.createdAt,
          },
        }))
      )
    } catch {
      res.status(500).json({ message: 'Failed to fetch shared files' })
    }
  }
)

// ---------------------------------------------------------------------------
// GET /:id/shares  →  GET /api/files/:id/shares
// Returns the list of users a file has been shared with (owner only).
// ---------------------------------------------------------------------------

router.get(
  '/:id/shares',
  requireAuth,
  async (req: Request, res: Response): Promise<void> => {
    const fileId = req.params['id']

    try {
      const file = await prisma.file.findFirst({
        where: { id: fileId, ownerId: req.userId },
      })

      if (!file) {
        res.status(404).json({ message: 'File not found' })
        return
      }

      const shares = await prisma.sharedFile.findMany({
        where: { fileId },
        include: { sharedWith: { select: { email: true } } },
        orderBy: { createdAt: 'asc' },
      })

      res.json(
        shares.map((s) => ({
          shareId: s.id,
          sharedWith: s.sharedWith.email,
          permission: s.permission,
          sharedAt: s.createdAt,
        }))
      )
    } catch {
      res.status(500).json({ message: 'Failed to fetch shares' })
    }
  }
)

// ---------------------------------------------------------------------------
// DELETE /:id/share/:shareId  →  DELETE /api/files/:id/share/:shareId
// ---------------------------------------------------------------------------

router.delete(
  '/:id/share/:shareId',
  requireAuth,
  async (req: Request, res: Response): Promise<void> => {
    const fileId = req.params['id']
    const shareId = req.params['shareId']

    try {
      // Find the SharedFile record, confirming:
      //  • the shareId matches the :shareId param
      //  • it belongs to the correct file (:id param)
      //  • the current user owns that file
      const sharedRecord = await prisma.sharedFile.findFirst({
        where: {
          id: shareId,
          fileId,
          file: { ownerId: req.userId },
        },
      })

      if (!sharedRecord) {
        res.status(404).json({ message: 'Share record not found' })
        return
      }

      await prisma.sharedFile.delete({ where: { id: sharedRecord.id } })

      res.status(204).send()
    } catch {
      res.status(500).json({ message: 'Failed to remove share' })
    }
  }
)

export default router
