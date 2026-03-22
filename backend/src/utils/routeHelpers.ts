/**
 * Shared helpers used by both the file and share route handlers.
 */

import { randomBytes, createCipheriv, createDecipheriv } from 'crypto'
import type { Request } from 'express'
import { aesDecrypt } from './crypto'
import type { EcdhPrivateKeyEnc, EncryptedData } from '../types'

/**
 * Parse and validate the X-Master-Key header.
 * Returns null if missing or decoded length is not 32 bytes.
 */
export function parseMasterKey(req: Request): Buffer | null {
  const header = req.headers['x-master-key']
  if (typeof header !== 'string' || !header) return null
  const key = Buffer.from(header, 'base64')
  return key.length === 32 ? key : null
}

/**
 * AES-256-GCM encrypt. Generates a fresh 96-bit IV every call (Paper [7]).
 */
export function gcmEncryptBuffer(
  plaintext: Buffer,
  key: Buffer
): { ciphertext: Buffer; iv: string; authTag: string } {
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
  return { ciphertext, iv: iv.toString('hex'), authTag: cipher.getAuthTag().toString('hex') }
}

/**
 * AES-256-GCM decrypt from raw Buffer. GCM auth tag verified before returning.
 */
export function gcmDecryptBuffer(
  ciphertext: Buffer,
  key: Buffer,
  ivHex: string,
  authTagHex: string
): Buffer {
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(ivHex, 'hex'))
  decipher.setAuthTag(Buffer.from(authTagHex, 'hex'))
  return Buffer.concat([decipher.update(ciphertext), decipher.final()])
}

/**
 * Decrypt a user's ECDH private key using their master key.
 * ecdhPrivateKeyEnc column stores JSON { ciphertext, iv, authTag, salt }.
 */
export function decryptUserPrivateKey(ecdhPrivateKeyEncJson: string, masterKey: Buffer): Buffer {
  const enc = JSON.parse(ecdhPrivateKeyEncJson) as EcdhPrivateKeyEnc
  const encData: EncryptedData = { ciphertext: enc.ciphertext, iv: enc.iv, authTag: enc.authTag }
  return aesDecrypt(encData, masterKey)
}
