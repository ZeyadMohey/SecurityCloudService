import {
  generateFileKey,
  sha256,
  encryptBuffer,
  decryptBuffer,
  deriveKeyFromPassword,
  timingSafeEqualBuffers,
} from '../utils/crypto'
import type { EncryptFileResult } from '../types'

/// ERRORS ///

/** Thrown when SHA-256 of decrypted content doesn't match the stored hash. */
export class IntegrityError extends Error {
  constructor(message = 'File integrity check failed: hash mismatch') {
    super(message)
    this.name = 'IntegrityError'
  }
}

/// Exported functions ///

/**
 * FOR TESTING
 * Encrypts a file buffer and wraps the file key under the user's master key.
 */
export function encryptFile(
  fileBuffer: Buffer,
  userPassword: string,
  userSaltHex: string
): EncryptFileResult {
  const fileKey = generateFileKey()
  const integrityHash = sha256(fileBuffer)
  const fileEnc = encryptBuffer(fileBuffer, fileKey)
  const masterKey = deriveKeyFromPassword(userPassword, Buffer.from(userSaltHex, 'hex'))
  const keyEnc = encryptBuffer(fileKey, masterKey)

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
 * FOR TESTING
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
  const masterKey = deriveKeyFromPassword(userPassword, Buffer.from(userSaltHex, 'hex'))
  const fileKey = decryptBuffer(
    Buffer.from(encryptedFileKey, 'hex'), masterKey,
    Buffer.from(fileKeyIv, 'hex'), Buffer.from(fileKeyAuthTag, 'hex')
  )
  const plaintext = decryptBuffer(
    encryptedFile, fileKey,
    Buffer.from(fileIv, 'hex'), Buffer.from(fileAuthTag, 'hex')
  )

  const actualHash = sha256(plaintext)
  if (
    actualHash.length !== expectedHashHex.length ||
    !timingSafeEqualBuffers(Buffer.from(actualHash, 'hex'), Buffer.from(expectedHashHex, 'hex'))
  ) {
    throw new IntegrityError()
  }

  return plaintext
}
