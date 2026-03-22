import { Router } from 'express'
import type { Request, Response } from 'express'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { PrismaClient } from '@prisma/client'
import { config } from '../config/env'
import {
  generateECDHKeyPair,
  deriveKeyFromPassword,
  encryptToHexObject,
  generateIV,
  randomBytes
} from '../utils/crypto'

const router = Router()
const prisma = new PrismaClient()


/// VALIDATION HELPERS ///

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

/**
 * min 8 chars, at least one uppercase, one lowercase, one digit.
 */
const PASSWORD_RE = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/

function validateEmail(email: string): boolean {
  return EMAIL_RE.test(email.trim())
}

function validatePassword(password: string): { ok: boolean; reason?: string } {
  if (password.length < 8) return { ok: false, reason: 'Password must be at least 8 characters' }
  if (!PASSWORD_RE.test(password))
    return {
      ok: false,
      reason: 'Password must contain at least one uppercase letter, one lowercase letter, and one number',
    }
  return { ok: true }
}


/// REGISTER ///

router.post('/register', async (req: Request, res: Response): Promise<void> => {
  const { email, password } = req.body as { email?: unknown; password?: unknown }

  if (typeof email !== 'string' || typeof password !== 'string') {
    res.status(400).json({ message: 'Email and password are required' })
    return
  }

  const normalizedEmail = email.trim().toLowerCase()

  if (!validateEmail(normalizedEmail)) {
    res.status(400).json({ message: 'Invalid email format' })
    return
  }

  const pwCheck = validatePassword(password)
  if (!pwCheck.ok) {
    res.status(400).json({ message: pwCheck.reason })
    return
  }

  try {
    const existing = await prisma.user.findUnique({ where: { email: normalizedEmail } })
    if (existing) {

      res.status(409).json({ message: 'Email already registered' })
      return
    }

    const passwordHash = await bcrypt.hash(password, 12)

    const { publicKey, privateKey } = generateECDHKeyPair()

    const salt = randomBytes(32)
    const masterKey = deriveKeyFromPassword(password, salt)

    const iv = generateIV()
    const encrypted = encryptToHexObject(Buffer.from(privateKey, 'hex'), masterKey, iv)

    const ecdhPrivateKeyEnc = JSON.stringify({
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      authTag: encrypted.authTag,
      salt: salt.toString('hex'),
    })

    const user = await prisma.user.create({
      data: {
        email: normalizedEmail,
        passwordHash,
        ecdhPublicKey: publicKey,
        ecdhPrivateKeyEnc,
      },
    })

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      config.jwtSecret,
      { expiresIn: '24h' }
    )

    res.status(201).json({
      token,
      user: {
        id: user.id,
        email: user.email,
        ecdhPublicKey: user.ecdhPublicKey,
        ecdhSalt: salt.toString('hex'),
      },
    })
  } catch {
    res.status(500).json({ message: 'Registration failed' })
  }
})


/// LOGIN ///

router.post('/login', async (req: Request, res: Response): Promise<void> => {
  const { email, password } = req.body as { email?: unknown; password?: unknown }

  if (typeof email !== 'string' || typeof password !== 'string') {
    res.status(400).json({ message: 'Email and password are required' })
    return
  }

  try {
    const normalizedEmail = email.trim().toLowerCase()
    const user = await prisma.user.findUnique({ where: { email: normalizedEmail } })

    // Compare even if user doesn't exist to prevent timing-based email enumeration
    const dummyHash = '$2a$12$invalidhashpaddingtomakeconstanttimeLookupXXXXXXXXXXXXX'
    const passwordMatch = await bcrypt.compare(
      password,
      user?.passwordHash ?? dummyHash
    )

    if (!user || !passwordMatch) {
      res.status(401).json({ message: 'Invalid credentials' })
      return
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      config.jwtSecret,
      { expiresIn: '24h' }
    )

    const { salt: ecdhSalt } = JSON.parse(user.ecdhPrivateKeyEnc) as { salt: string }

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        ecdhPublicKey: user.ecdhPublicKey,
        ecdhSalt,
      },
    });
  } catch {
    res.status(500).json({ message: 'Login failed' })
  }
})

export default router
