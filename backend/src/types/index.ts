export interface JwtPayload {
  userId: string
  email: string
  iat?: number
  exp?: number
}

export interface XssScanResult {
  is_xss: boolean
  confidence: number
}

export interface EncryptedData {
  ciphertext: string
  iv: string
  authTag: string
}

export interface EcdhPrivateKeyEnc {
  ciphertext: string
  iv: string
  authTag: string
  salt: string
}

export interface SharedKeyBundle {
  encryptedFileKey: string  // hex
  iv: string                // hex, 12 bytes
  authTag: string           // hex, 16 bytes
  hkdfSalt: string          // hex, 32 bytes
}

export interface EncryptFileResult {
  encryptedFile: Buffer
  encryptedFileKey: string  // hex ciphertext of the wrapped file key
  fileKeyIv: string
  fileKeyAuthTag: string
  fileIv: string
  fileAuthTag: string
  integrityHash: string     // SHA-256 of plaintext
}
