/**
 * Database seed — creates two test users with full ECDH key pairs.
 *
 * Implements ECC key pair generation from Paper [9] (Abualkas & B.D.):
 * - secp256k1 ECDH key pair generated at "registration" time
 * - Private key encrypted with AES-256-GCM using a PBKDF2-derived master key (Paper 7)
 * - ecdhPrivateKeyEnc stored as JSON: { iv, authTag, ciphertext, salt } — all hex strings
 */

import { PrismaClient } from '@prisma/client'
import bcrypt from 'bcryptjs'
import {
  createECDH,
  randomBytes,
  pbkdf2Sync,
  createCipheriv,
} from 'crypto'

const prisma = new PrismaClient()

interface EncryptedPrivateKey {
  ciphertext: string
  iv: string
  authTag: string
  salt: string
}

function generateECDHKeyPair(): { publicKey: string; privateKey: string } {
  const ecdh = createECDH('secp256k1')
  ecdh.generateKeys()
  return {
    publicKey: ecdh.getPublicKey('hex'),
    privateKey: ecdh.getPrivateKey('hex'),
  }
}

function deriveKeyFromPassword(password: string, salt: Buffer): Buffer {
  return pbkdf2Sync(password, salt, 100_000, 32, 'sha512')
}

function encryptPrivateKey(privateKeyHex: string, masterKey: Buffer): EncryptedPrivateKey {
  const iv = randomBytes(12) // 96-bit IV for AES-256-GCM (Paper 7 — never reuse IVs)
  const cipher = createCipheriv('aes-256-gcm', masterKey, iv)
  const privateKeyBuf = Buffer.from(privateKeyHex, 'hex')
  const ciphertext = Buffer.concat([cipher.update(privateKeyBuf), cipher.final()])
  const authTag = cipher.getAuthTag() // GCM auth tag — detects tampering (Paper 7)
  return {
    ciphertext: ciphertext.toString('hex'),
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex'),
    salt: '', // salt stored separately; populated by caller
  }
}

async function createUser(email: string, password: string): Promise<void> {
  const existing = await prisma.user.findUnique({ where: { email } })
  if (existing) {
    console.log(`  User ${email} already exists — skipping`)
    return
  }

  // 1. Hash password with bcrypt (cost factor 12)
  const passwordHash = await bcrypt.hash(password, 12)

  // 2. Generate ECDH key pair (secp256k1 — Paper 9)
  const { publicKey, privateKey } = generateECDHKeyPair()

  // 3. Derive master key from password via PBKDF2 (Paper 6 — key derivation)
  //    PBKDF2(password, salt, 100_000 iterations, 32 bytes, SHA-512)
  const salt = randomBytes(32)
  const masterKey = deriveKeyFromPassword(password, salt)

  // 4. Encrypt private key with AES-256-GCM (NOT ECB — Paper 7)
  const encrypted = encryptPrivateKey(privateKey, masterKey)
  encrypted.salt = salt.toString('hex')

  // 5. Store encrypted private key as JSON
  const ecdhPrivateKeyEnc = JSON.stringify(encrypted)

  await prisma.user.create({
    data: {
      email,
      passwordHash,
      ecdhPublicKey: publicKey,
      ecdhPrivateKeyEnc,
    },
  })

  console.log(`  Created user: ${email}`)
  console.log(`    ECDH public key (secp256k1): ${publicKey.slice(0, 20)}...`)
  console.log(`    Private key encrypted with AES-256-GCM (IV: ${encrypted.iv.slice(0, 12)}...)`)
}

async function main(): Promise<void> {
  console.log('Seeding database...\n')

  const testUsers = [
    { email: 'alice@test.com', password: 'Password123!' },
    { email: 'bob@test.com',   password: 'Password123!' },
  ]

  for (const user of testUsers) {
    await createUser(user.email, user.password)
  }

  console.log('\nSeed complete.')
  console.log('Test credentials: alice@test.com / bob@test.com — Password123!')
}

main()
  .catch((err) => {
    console.error('Seed failed:', err)
    process.exit(1)
  })
  .finally(() => {
    void prisma.$disconnect()
  })
