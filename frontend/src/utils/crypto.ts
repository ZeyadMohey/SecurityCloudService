/**
 * Client-side cryptography — Web Crypto API only, no third-party libraries.
 *
 * deriveMasterKey uses PBKDF2 with identical parameters to the server-side
 * pbkdf2Sync call in backend/src/services/encryption.ts:
 *   - HMAC-SHA-512 PRF
 *   - 100 000 iterations
 *   - 256-bit output key (AES-GCM)
 *
 * This means the base64 bytes sent in X-Master-Key are exactly the 32 bytes
 * the server would derive from the same password + salt pair.
 */

/**
 * Derive a 256-bit AES-GCM master key from a password and hex-encoded salt.
 *
 * @param password - Plaintext password entered by the user.
 * @param saltHex  - 64-char hex string from the login/register response
 *                   (User.ecdhSalt). Not secret — prevents rainbow tables.
 */
export async function deriveMasterKey(password: string, saltHex: string): Promise<CryptoKey> {
  const enc = new TextEncoder()
  const saltBytes = hexToBytes(saltHex)

  // Import the raw password bytes as PBKDF2 key material
  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  )

  // Derive a 256-bit AES-GCM key — extractable so we can export it for the header
  return window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltBytes,
      iterations: 100_000,
      hash: 'SHA-512',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  )
}

/**
 * Export a CryptoKey to a base64 string for use in the X-Master-Key header.
 * The server base64-decodes this to get the raw 32-byte key.
 */
export async function exportKeyAsBase64(key: CryptoKey): Promise<string> {
  const raw = await window.crypto.subtle.exportKey('raw', key)
  const bytes = new Uint8Array(raw)
  let binary = ''
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const buf = new ArrayBuffer(hex.length / 2)
  const bytes = new Uint8Array(buf)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16)
  }
  return bytes
}
