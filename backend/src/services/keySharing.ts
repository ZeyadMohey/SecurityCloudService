/**
 * ECDH-based file-key sharing (Paper [9] — Abualkas & B.D., ECC-AES hybrid)
 */

import { randomBytes, createECDH, createCipheriv, createDecipheriv, hkdfSync } from 'crypto'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** JSON stored in SharedFile.encryptedFileKey. */
export interface SharedKeyBundle {
  encryptedFileKey: string  // hex
  iv: string                // hex, 12 bytes
  authTag: string           // hex, 16 bytes
  hkdfSalt: string          // hex, 32 bytes
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function gcmEncrypt(plaintext: Buffer, key: Buffer) {
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
  return { ciphertext, iv, authTag: cipher.getAuthTag() }
}

function gcmDecrypt(ciphertext: Buffer, key: Buffer, iv: Buffer, authTag: Buffer): Buffer {
  const decipher = createDecipheriv('aes-256-gcm', key, iv)
  decipher.setAuthTag(authTag)
  return Buffer.concat([decipher.update(ciphertext), decipher.final()])
}

function deriveSharedKey(sharedSecret: Buffer, hkdfSalt: Buffer): Buffer {
  return Buffer.from(
    hkdfSync('sha256', sharedSecret, hkdfSalt, Buffer.from('securevault-share'), 32)
  )
}

// ---------------------------------------------------------------------------
// Exported functions
// ---------------------------------------------------------------------------

/**
 * Re-encrypts a file key for a recipient using ECDH key exchange.
 * ECDH(sender_private, recipient_public) → HKDF → AES-256-GCM wrap.
 */
export function encryptFileKeyForSharing(
  fileKey: Buffer,
  senderPrivateKey: Buffer,
  recipientPublicKey: Buffer
): SharedKeyBundle {
  const ecdh = createECDH('secp256k1')
  ecdh.setPrivateKey(senderPrivateKey)
  const sharedSecret = ecdh.computeSecret(recipientPublicKey)

  const hkdfSalt = randomBytes(32)
  const derivedKey = deriveSharedKey(sharedSecret, hkdfSalt)
  const { ciphertext, iv, authTag } = gcmEncrypt(fileKey, derivedKey)

  return {
    encryptedFileKey: ciphertext.toString('hex'),
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex'),
    hkdfSalt: hkdfSalt.toString('hex'),
  }
}

/**
 * Recovers a shared file key using the recipient's ECDH private key.
 * ECDH(recipient_private, sender_public) yields the same shared secret.
 */
export function decryptSharedFileKey(
  bundle: SharedKeyBundle,
  recipientPrivateKey: Buffer,
  senderPublicKey: Buffer
): Buffer {
  const ecdh = createECDH('secp256k1')
  ecdh.setPrivateKey(recipientPrivateKey)
  const sharedSecret = ecdh.computeSecret(senderPublicKey)
  const derivedKey = deriveSharedKey(sharedSecret, Buffer.from(bundle.hkdfSalt, 'hex'))

  return gcmDecrypt(
    Buffer.from(bundle.encryptedFileKey, 'hex'),
    derivedKey,
    Buffer.from(bundle.iv, 'hex'),
    Buffer.from(bundle.authTag, 'hex')
  )
}
