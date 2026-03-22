/**
 * File encryption/decryption — AES-256-GCM + PBKDF2 (Papers [6], [7], [8], [10])
 */

import {
  randomBytes, createHash, createCipheriv, createDecipheriv,
  pbkdf2Sync, timingSafeEqual,
} from 'crypto'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface EncryptFileResult {
  encryptedFile: Buffer
  encryptedFileKey: string  // hex ciphertext of the wrapped file key
  fileKeyIv: string
  fileKeyAuthTag: string
  fileIv: string
  fileAuthTag: string
  integrityHash: string     // SHA-256 of plaintext
}

// ---------------------------------------------------------------------------
// Exported error
// ---------------------------------------------------------------------------

/** Thrown when SHA-256 of decrypted content doesn't match the stored hash. */
export class IntegrityError extends Error {
  constructor(message = 'File integrity check failed: hash mismatch') {
    super(message)
    this.name = 'IntegrityError'
  }
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

function deriveMasterKey(password: string, saltHex: string): Buffer {
  return pbkdf2Sync(password, Buffer.from(saltHex, 'hex'), 100_000, 32, 'sha512')
}

// ---------------------------------------------------------------------------
// Exported functions
// ---------------------------------------------------------------------------

/**
 * Encrypts a file buffer and wraps the file key under the user's master key.
 * Per-file key isolation (Paper [10]); AES-256-GCM (Paper [7]); SHA-256 hash (Paper [8]).
 */
export function encryptFile(
  fileBuffer: Buffer,
  userPassword: string,
  userSaltHex: string
): EncryptFileResult {
  const fileKey = randomBytes(32)
  const integrityHash = createHash('sha256').update(fileBuffer).digest('hex')
  const fileEnc = gcmEncrypt(fileBuffer, fileKey)
  const masterKey = deriveMasterKey(userPassword, userSaltHex)
  const keyEnc = gcmEncrypt(fileKey, masterKey)

  return {
    encryptedFile: fileEnc.ciphertext,
    encryptedFileKey: keyEnc.ciphertext.toString('hex'),
    fileKeyIv: keyEnc.iv.toString('hex'),
    fileKeyAuthTag: keyEnc.authTag.toString('hex'),
    fileIv: fileEnc.iv.toString('hex'),
    fileAuthTag: fileEnc.authTag.toString('hex'),
    integrityHash,
  }
}

/**
 * Decrypts a file and verifies its SHA-256 integrity hash (Papers [7], [8]).
 * @throws {IntegrityError} on hash mismatch
 * @throws {Error} on GCM auth-tag failure
 */
export function decryptFile(
  encryptedFile: Buffer,
  encryptedFileKey: string,
  fileKeyIv: string,
  fileKeyAuthTag: string,
  fileIv: string,
  fileAuthTag: string,
  userPassword: string,
  userSaltHex: string,
  expectedHashHex: string
): Buffer {
  const masterKey = deriveMasterKey(userPassword, userSaltHex)
  const fileKey = gcmDecrypt(
    Buffer.from(encryptedFileKey, 'hex'), masterKey,
    Buffer.from(fileKeyIv, 'hex'), Buffer.from(fileKeyAuthTag, 'hex')
  )
  const plaintext = gcmDecrypt(
    encryptedFile, fileKey,
    Buffer.from(fileIv, 'hex'), Buffer.from(fileAuthTag, 'hex')
  )

  const actualHash = createHash('sha256').update(plaintext).digest('hex')
  if (
    actualHash.length !== expectedHashHex.length ||
    !timingSafeEqual(Buffer.from(actualHash, 'hex'), Buffer.from(expectedHashHex, 'hex'))
  ) {
    throw new IntegrityError()
  }

  return plaintext
}
