import {
  randomBytes as nodeRandomBytes,
  createHash,
  createCipheriv,
  createDecipheriv,
  createECDH,
  pbkdf2Sync,
  hkdfSync,
  timingSafeEqual,
} from 'crypto'
import type { EncryptedData } from '../types'

export const randomBytes = nodeRandomBytes

/** 
 * 
 * Generate a  256-bit AES key 
 * */
export function generateFileKey(): Buffer {
  return nodeRandomBytes(32)
}

/** 
 * 
 * Generate a random 96-bit IV for AES 
 * */
export function generateIV(): Buffer {
  return nodeRandomBytes(12)
}

/** 
 *
 * Compute SHA-256 hash of a buffer 
 * */
export function sha256(data: Buffer): string {
  return createHash('sha256').update(data).digest('hex')
}

/** 
 *
 * Encrypt a buffer with AES-256-GCM.
 * Returns raw Buffer objects.
 * Generates a fresh 96-bit IV automatically if one is not provided.
 * */
export function encryptBuffer(plaintext: Buffer, key: Buffer, iv?: Buffer) {
  const actualIv = iv || generateIV()
  const cipher = createCipheriv('aes-256-gcm', key, actualIv)
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
  return { ciphertext, iv: actualIv, authTag: cipher.getAuthTag() }
}

/** 
 *
 * Decrypt an AES-256-GCM ciphertext buffer.
 * Takes raw Buffer objects and verifies the GCM auth tag.
 * */
export function decryptBuffer(ciphertext: Buffer, key: Buffer, iv: Buffer, authTag: Buffer): Buffer {
  const decipher = createDecipheriv('aes-256-gcm', key, iv)
  decipher.setAuthTag(authTag)
  return Buffer.concat([decipher.update(ciphertext), decipher.final()])
}

/** 
 *
 * Encrypt data with AES-256-GCM.
 * Returns hex strings bundled in an EncryptedData object, useful for JSON serialization.
 * */
export function encryptToHexObject(plaintext: Buffer, key: Buffer, iv: Buffer): EncryptedData {
  const enc = encryptBuffer(plaintext, key, iv)
  return {
    ciphertext: enc.ciphertext.toString('hex'),
    iv: enc.iv.toString('hex'),
    authTag: enc.authTag.toString('hex'),
  }
}

/**
 *
 * Decrypt AES-256-GCM ciphertext from an EncryptedData object containing hex strings.
 */
export function decryptFromHexObject(encrypted: EncryptedData, key: Buffer): Buffer {
  return decryptBuffer(
    Buffer.from(encrypted.ciphertext, 'hex'),
    key,
    Buffer.from(encrypted.iv, 'hex'),
    Buffer.from(encrypted.authTag, 'hex')
  )
}

/**
 * Derive a 256-bit master key from a password using PBKDF2.
 * 100,000 iterations with SHA-512 suitable for key derivation.
 */
export function deriveKeyFromPassword(password: string, salt: Buffer): Buffer {
  return pbkdf2Sync(password, salt, 100_000, 32, 'sha512')
}

/**
 *
 * Generate an ECDH key pair
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
 *
 * Compute ECDH shared secret from one party's private key and the other's public key.
 */
export function computeECDHSharedSecret(privateKeyHex: string, publicKeyHex: string): Buffer {
  const ecdh = createECDH('secp256k1')
  ecdh.setPrivateKey(Buffer.from(privateKeyHex, 'hex'))
  return ecdh.computeSecret(Buffer.from(publicKeyHex, 'hex'))
}

/**
 *
 * Derive an AES key from an ECDH shared secret using HKDF
 */
export function hkdfDeriveKey(sharedSecret: Buffer, info: string, salt: Buffer = Buffer.alloc(0)): Buffer {
  const derived = hkdfSync('sha256', sharedSecret, salt, Buffer.from(info), 32)
  return Buffer.from(derived)
}

/**
 * Compare two buffers in constant time
 */
export function timingSafeEqualBuffers(a: Buffer, b: Buffer): boolean {
  return timingSafeEqual(a, b)
}
