// AuthenticatedRequest is superseded by types/express.d.ts which extends the
// global Express.Request interface directly — no casting or wrapper needed.

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
