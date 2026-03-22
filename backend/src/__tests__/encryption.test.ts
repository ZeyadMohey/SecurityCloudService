/**
 * encryption.test.ts — Unit tests for crypto services.
 * No HTTP, no database — pure Node.js crypto tests.
 *
 * Papers covered:
 *  [6]  AES-256-GCM encryption (not ECB)
 *  [7]  GCM auth-tag tamper detection (MEGA vulnerability fix)
 *  [8]  SHA-256 integrity hash verification
 *  [9]  ECDH key exchange for file sharing
 *  [10] Per-file encryption keys
 */
import { randomBytes, createECDH } from 'crypto'
import { encryptFile, decryptFile, IntegrityError } from '../services/fileEncryption'
import { encryptFileKeyForSharing, decryptSharedFileKey } from '../services/keySharing'
import { aesEncrypt, aesDecrypt, generateIV } from '../utils/crypto'

// Stable test fixtures — re-generated once per suite for performance
const PASSWORD = 'TestPass1'
const SALT_HEX = randomBytes(32).toString('hex')
const PLAINTEXT = Buffer.from('Hello, SecureVault! This is a test file.')

// ── encrypt / decrypt roundtrip ────────────────────────────────────────────

describe('encryptFile / decryptFile roundtrip (Papers [6], [8], [10])', () => {
  it('decrypts back to the original plaintext', () => {
    const result = encryptFile(PLAINTEXT, PASSWORD, SALT_HEX)
    const recovered = decryptFile(
      result.encryptedFile,
      result.encryptedFileKey,
      result.fileKeyIv,
      result.fileKeyAuthTag,
      result.fileIv,
      result.fileAuthTag,
      PASSWORD,
      SALT_HEX,
      result.integrityHash,
    )
    expect(recovered).toEqual(PLAINTEXT)
  })

  it('produces non-empty ciphertext different from plaintext', () => {
    const result = encryptFile(PLAINTEXT, PASSWORD, SALT_HEX)
    expect(result.encryptedFile.length).toBeGreaterThan(0)
    expect(result.encryptedFile.equals(PLAINTEXT)).toBe(false)
  })

  it('stores a 64-char hex SHA-256 integrity hash (Paper [8])', () => {
    const result = encryptFile(PLAINTEXT, PASSWORD, SALT_HEX)
    expect(result.integrityHash).toMatch(/^[0-9a-f]{64}$/)
  })
})

// ── integrity hash verification ─────────────────────────────────────────────

describe('integrity hash verification (Paper [8])', () => {
  it('passes for an unmodified ciphertext', () => {
    const result = encryptFile(PLAINTEXT, PASSWORD, SALT_HEX)
    expect(() =>
      decryptFile(
        result.encryptedFile, result.encryptedFileKey,
        result.fileKeyIv, result.fileKeyAuthTag,
        result.fileIv, result.fileAuthTag,
        PASSWORD, SALT_HEX, result.integrityHash,
      )
    ).not.toThrow()
  })

  it('throws IntegrityError when the stored hash is tampered (1 hex char changed)', () => {
    const result = encryptFile(PLAINTEXT, PASSWORD, SALT_HEX)

    // Flip the first character of the stored hash
    const firstChar = result.integrityHash[0]
    const tamperedHash = (firstChar === 'a' ? 'b' : 'a') + result.integrityHash.slice(1)

    expect(() =>
      decryptFile(
        result.encryptedFile, result.encryptedFileKey,
        result.fileKeyIv, result.fileKeyAuthTag,
        result.fileIv, result.fileAuthTag,
        PASSWORD, SALT_HEX, tamperedHash,
      )
    ).toThrow(IntegrityError)
  })
})

// ── per-file keys — Paper [10] ───────────────────────────────────────────────

describe('per-file encryption keys (Paper [10])', () => {
  it('two files encrypted with different random keys', () => {
    const r1 = encryptFile(PLAINTEXT, PASSWORD, SALT_HEX)
    const r2 = encryptFile(PLAINTEXT, PASSWORD, SALT_HEX)

    // encryptedFileKey is the WRAPPED key (AES-GCM ciphertext of the file key).
    // Because each file key and wrapping IV are random, the wrapped keys differ.
    expect(r1.encryptedFileKey).not.toBe(r2.encryptedFileKey)
    expect(r1.fileIv).not.toBe(r2.fileIv)
  })

  it('wrong master key (wrong password) fails to decrypt the file key', () => {
    const result = encryptFile(PLAINTEXT, PASSWORD, SALT_HEX)
    expect(() =>
      decryptFile(
        result.encryptedFile, result.encryptedFileKey,
        result.fileKeyIv, result.fileKeyAuthTag,
        result.fileIv, result.fileAuthTag,
        'WrongPass9', SALT_HEX, result.integrityHash,
      )
    ).toThrow()
  })
})

// ── AES-GCM auth-tag tamper detection — Paper [7] (MEGA vulnerability fix) ──

describe('AES-GCM rejects wrong auth tag (Paper [7])', () => {
  it('throws when auth tag is corrupted (simulating ciphertext tampering)', () => {
    const key = randomBytes(32)
    const iv  = generateIV()
    const plaintext = Buffer.from('sensitive data')
    const encrypted = aesEncrypt(plaintext, key, iv)

    // Corrupt a single byte of the auth tag
    const badTag = Buffer.from(encrypted.authTag, 'hex')
    badTag[0] ^= 0xff
    const tampered = { ...encrypted, authTag: badTag.toString('hex') }

    expect(() => aesDecrypt(tampered, key)).toThrow()
  })

  it('throws when ciphertext is modified (1 byte flip, tag no longer valid)', () => {
    const key = randomBytes(32)
    const iv  = generateIV()
    const encrypted = aesEncrypt(Buffer.from('original content'), key, iv)

    // Flip bit in ciphertext — GCM auth tag will no longer verify
    const badCt = Buffer.from(encrypted.ciphertext, 'hex')
    badCt[0] ^= 0x01
    const tampered = { ...encrypted, ciphertext: badCt.toString('hex') }

    expect(() => aesDecrypt(tampered, key)).toThrow()
  })
})

// ── ECDH key exchange for sharing — Paper [9] ────────────────────────────────

describe('ECDH file-key sharing (Paper [9])', () => {
  const genKeyPair = () => {
    const ecdh = createECDH('secp256k1')
    ecdh.generateKeys()
    return { privateKey: ecdh.getPrivateKey(), publicKey: ecdh.getPublicKey() }
  }

  it('encrypts and decrypts file key via ECDH shared secret', () => {
    const alice = genKeyPair()
    const bob   = genKeyPair()
    const fileKey = randomBytes(32)

    const bundle = encryptFileKeyForSharing(fileKey, alice.privateKey, bob.publicKey)
    const recovered = decryptSharedFileKey(bundle, bob.privateKey, alice.publicKey)

    expect(recovered).toEqual(fileKey)
  })

  it('ECDH is commutative: ECDH(A_priv, B_pub) == ECDH(B_priv, A_pub)', () => {
    const alice = genKeyPair()
    const bob   = genKeyPair()
    const fileKey = randomBytes(32)

    // Encrypt from Alice's side
    const bundle = encryptFileKeyForSharing(fileKey, alice.privateKey, bob.publicKey)
    // Bob decrypts using his private key and Alice's public key
    const recovered = decryptSharedFileKey(bundle, bob.privateKey, alice.publicKey)
    expect(recovered).toEqual(fileKey)
  })

  it('wrong recipient private key cannot decrypt the shared file key', () => {
    const alice   = genKeyPair()
    const bob     = genKeyPair()
    const mallory = genKeyPair()
    const fileKey = randomBytes(32)

    const bundle = encryptFileKeyForSharing(fileKey, alice.privateKey, bob.publicKey)

    // Mallory uses her own private key — ECDH produces a different shared secret
    expect(() => decryptSharedFileKey(bundle, mallory.privateKey, alice.publicKey)).toThrow()
  })
})
