import type { Request } from 'express'
import { decryptFromHexObject } from './crypto'
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
 * Decrypt a user's ECDH private key using their master key.
 * ecdhPrivateKeyEnc column stores JSON { ciphertext, iv, authTag, salt }.
 */
export function decryptUserPrivateKey(ecdhPrivateKeyEncJson: string, masterKey: Buffer): Buffer {
  const enc = JSON.parse(ecdhPrivateKeyEncJson) as EcdhPrivateKeyEnc
  const encData: EncryptedData = { ciphertext: enc.ciphertext, iv: enc.iv, authTag: enc.authTag }
  return decryptFromHexObject(encData, masterKey)
}
