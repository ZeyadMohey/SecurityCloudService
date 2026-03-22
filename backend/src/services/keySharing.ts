import { randomBytes } from 'crypto'
import {
  encryptBuffer,
  decryptBuffer,
  computeECDHSharedSecret,
  hkdfDeriveKey
} from '../utils/crypto'
import type { SharedKeyBundle } from '../types'

function deriveSharedKey(sharedSecret: Buffer, hkdfSalt: Buffer): Buffer {
  return hkdfDeriveKey(sharedSecret, 'securevault-share', hkdfSalt)
}

/**
 * Encrypts a file key for a recipient using ECDH key exchange.
 * ECDH(sender_private, recipient_public)
 */
export function encryptFileKeyForSharing(
  fileKey: Buffer,
  senderPrivateKey: Buffer,
  recipientPublicKey: Buffer
): SharedKeyBundle {
  const sharedSecret = computeECDHSharedSecret(
    senderPrivateKey.toString('hex'),
    recipientPublicKey.toString('hex')
  )

  const hkdfSalt = randomBytes(32)
  const derivedKey = deriveSharedKey(sharedSecret, hkdfSalt)
  const { ciphertext, iv, authTag } = encryptBuffer(fileKey, derivedKey)

  return {
    encryptedFileKey: ciphertext.toString('hex'),
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex'),
    hkdfSalt: hkdfSalt.toString('hex'),
  }
}

/**
 * Decrypts a shared file key using the ECDH key exchange.
 * ECDH(recipient_private, sender_public)
 */
export function decryptSharedFileKey(
  bundle: SharedKeyBundle,
  recipientPrivateKey: Buffer,
  senderPublicKey: Buffer
): Buffer {
  const sharedSecret = computeECDHSharedSecret(
    recipientPrivateKey.toString('hex'),
    senderPublicKey.toString('hex')
  )
  const derivedKey = deriveSharedKey(sharedSecret, Buffer.from(bundle.hkdfSalt, 'hex'))

  return decryptBuffer(
    Buffer.from(bundle.encryptedFileKey, 'hex'),
    derivedKey,
    Buffer.from(bundle.iv, 'hex'),
    Buffer.from(bundle.authTag, 'hex')
  )
}
