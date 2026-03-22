import {
  randomBytes,
  createHash,
  createCipheriv,
  createDecipheriv,
  createECDH,
  pbkdf2Sync,
  hkdfSync,
} from 'crypto'
import type { EncryptedData } from '../types'

/** Generate a cryptographically random 256-bit AES key */
export function generateFileKey(): Buffer {
  return randomBytes(32)
}

/** Generate a random 96-bit IV for AES-256-GCM */
export function generateIV(): Buffer {
  return randomBytes(12)
}

/** Compute SHA-256 hash of a buffer — used for integrity verification (Paper 8) */
export function sha256(data: Buffer): string {
  return createHash('sha256').update(data).digest('hex')
}

/** Encrypt data with AES-256-GCM. Returns ciphertext, IV, and auth tag. */
export function aesEncrypt(plaintext: Buffer, key: Buffer, iv: Buffer): EncryptedData {
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
  const authTag = cipher.getAuthTag()
  return {
    ciphertext: ciphertext.toString('hex'),
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex'),
  }
}

/** Decrypt AES-256-GCM ciphertext, verifying the auth tag. */
export function aesDecrypt(encrypted: EncryptedData, key: Buffer): Buffer {
  const decipher = createDecipheriv(
    'aes-256-gcm',
    key,
    Buffer.from(encrypted.iv, 'hex')
  )
  decipher.setAuthTag(Buffer.from(encrypted.authTag, 'hex'))
  return Buffer.concat([
    decipher.update(Buffer.from(encrypted.ciphertext, 'hex')),
    decipher.final(),
  ])
}

/**
 * Derive a 256-bit master key from a password using PBKDF2.
 * 100,000 iterations with SHA-512 — suitable for key derivation (Paper 6).
 */
export function deriveKeyFromPassword(password: string, salt: Buffer): Buffer {
  return pbkdf2Sync(password, salt, 100_000, 32, 'sha512')
}

/**
 * Generate an ECDH key pair (secp256k1 — Paper 9).
 */
export function generateECDHKeyPair(): { publicKey: string; privateKey: string } {
  const ecdh = createECDH('secp256k1')
  ecdh.generateKeys()
  return {
    publicKey: ecdh.getPublicKey('hex'),
    privateKey: ecdh.getPrivateKey('hex'),
  }
}

/**
 * Compute ECDH shared secret from one party's private key and the other's public key.
 */
export function computeECDHSharedSecret(privateKeyHex: string, publicKeyHex: string): Buffer {
  const ecdh = createECDH('secp256k1')
  ecdh.setPrivateKey(Buffer.from(privateKeyHex, 'hex'))
  return ecdh.computeSecret(Buffer.from(publicKeyHex, 'hex'))
}

/**
 * Derive an AES key from an ECDH shared secret using HKDF (Paper 9).
 */
export function hkdfDeriveKey(sharedSecret: Buffer, info: string): Buffer {
  const derived = hkdfSync('sha256', sharedSecret, Buffer.alloc(0), Buffer.from(info), 32)
  return Buffer.from(derived)
}
