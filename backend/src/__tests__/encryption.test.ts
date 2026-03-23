/**
 * Tests Encryption Functions
 * No HTTP, no database
 *
 */
import { randomBytes, createECDH } from 'crypto'
import { encryptFile, decryptFile, IntegrityError } from '../services/fileEncryption'
import { encryptFileKeyForSharing, decryptSharedFileKey } from '../services/keySharing'
import { encryptToHexObject, decryptFromHexObject, generateIV } from '../utils/crypto'

// CONSTANTS
const PASSWORD = 'TestPass1'
const SALT_HEX = randomBytes(32).toString('hex')
const PLAINTEXT = Buffer.from('Hello, SecureVault! This is a test file.')

// encrypt / decrypt roundtrip

describe('encryptFile / decryptFile roundtrip ', () => {
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

// integrity hash verification

describe('integrity hash verification', () => {
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

// per-file keys

describe('per-file encryption keys', () => {
  it('two files encrypted with different random keys', () => {
    const r1 = encryptFile(PLAINTEXT, PASSWORD, SALT_HEX)
    const r2 = encryptFile(PLAINTEXT, PASSWORD, SALT_HEX)

    // encryptedFileKey is the WRAPPED key
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

// AES-GCM auth-tag tamper

describe('AES-GCM rejects wrong auth tag', () => {
  it('throws when auth tag is corrupted (simulating ciphertext tampering)', () => {
    const key = randomBytes(32)
    const iv  = generateIV()
    const plaintext = Buffer.from('sensitive data')
    const encrypted = encryptToHexObject(plaintext, key, iv)

    // Corrupt a single byte of the auth tag
    const badTag = Buffer.from(encrypted.authTag, 'hex')
    badTag[0] ^= 0xff
    const tampered = { ...encrypted, authTag: badTag.toString('hex') }

    expect(() => decryptFromHexObject(tampered, key)).toThrow()
  })

  it('throws when ciphertext is modified (1 byte flip, tag no longer valid)', () => {
    const key = randomBytes(32)
    const iv  = generateIV()
    const encrypted = encryptToHexObject(Buffer.from('original content'), key, iv)

    // Flip bit in ciphertext   GCM auth tag will no longer verify
    const badCt = Buffer.from(encrypted.ciphertext, 'hex')
    badCt[0] ^= 0x01
    const tampered = { ...encrypted, ciphertext: badCt.toString('hex') }

    expect(() => decryptFromHexObject(tampered, key)).toThrow()
  })
})

// ECDH key exchange for sharing

describe('ECDH file-key sharing', () => {
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

    // Mallory uses her own private key
    expect(() => decryptSharedFileKey(bundle, mallory.privateKey, alice.publicKey)).toThrow()
  })
})
