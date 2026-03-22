/**
 * Tests File Sharing
 *
 * Requires a running PostgreSQL instance (DATABASE_URL env var).
 * Run inside Docker:  docker compose exec backend npm test
 */
import { pbkdf2Sync } from 'crypto'
import request from 'supertest'
import { cleanupTestUsers, disconnectDb } from './helpers/testDb'
import app from '../app'

type FetchResponse = Awaited<ReturnType<typeof fetch>>

/// HELPERS ///

const EMAIL_PREFIX = 'jest_share_'
let emailCounter = 0
const uniqueEmail = () =>
  `${EMAIL_PREFIX}${Date.now()}_${++emailCounter}@test.com`

const PASSWORD = 'SharePass1'

/** Register a user and return their JWT + derived master key (base64) */
async function registerUser(email: string): Promise<{ token: string; masterKeyB64: string }> {
  const res = await request(app)
    .post('/api/auth/register')
    .send({ email, password: PASSWORD })
  expect(res.status).toBe(201)

  const { ecdhSalt } = res.body.user as { ecdhSalt: string }
  const masterKey = pbkdf2Sync(PASSWORD, Buffer.from(ecdhSalt, 'hex'), 100_000, 32, 'sha512')

  return { token: res.body.token as string, masterKeyB64: masterKey.toString('base64') }
}

/** Upload a file and return the file ID */
async function uploadFile(
  token: string,
  masterKeyB64: string,
  content: string,
  filename = 'test.txt',
): Promise<string> {
  // ML scan is mocked — returns benign for all uploads
  jest.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
    ok: true,
    json: async () => ({ is_xss: false, confidence: 0.01 }),
  } as unknown as FetchResponse)

  const res = await request(app)
    .post('/api/files/upload')
    .set('Authorization', `Bearer ${token}`)
    .set('X-Master-Key', masterKeyB64)
    .attach('file', Buffer.from(content), { filename, contentType: 'text/plain' })

  expect(res.status).toBe(201)
  return res.body.id as string
}

// Test setup / teardown

afterEach(() => jest.restoreAllMocks())

afterAll(async () => {
  await cleanupTestUsers(EMAIL_PREFIX)
  await disconnectDb()
})

// Full sharing flow

describe('Full sharing flow', () => {
  it('User A uploads -> shares with User B -> User B downloads original content', async () => {
    const emailA = uniqueEmail()
    const emailB = uniqueEmail()
    const originalContent = 'Super secret file content for sharing test!'

    const userA = await registerUser(emailA)
    const userB = await registerUser(emailB)

    // Upload as User A
    const fileId = await uploadFile(userA.token, userA.masterKeyB64, originalContent)

    // Share with User B
    const shareRes = await request(app)
      .post(`/api/files/${fileId}/share`)
      .set('Authorization', `Bearer ${userA.token}`)
      .set('X-Master-Key', userA.masterKeyB64)
      .send({ email: emailB, permission: 'download' })

    expect(shareRes.status).toBe(201)
    expect(shareRes.body.sharedWith).toBe(emailB)

    // User B downloads 
    const downloadRes = await request(app)
      .get(`/api/files/${fileId}/download`)
      .set('Authorization', `Bearer ${userB.token}`)
      .set('X-Master-Key', userB.masterKeyB64)

    expect(downloadRes.status).toBe(200)

    expect(downloadRes.text).toBe(originalContent)
  })
})

// Unauthorized access

describe('Authorization enforcement', () => {
  it('User C cannot download a file they were never shared with', async () => {
    const emailA = uniqueEmail()
    const emailC = uniqueEmail()

    const userA = await registerUser(emailA)
    const userC = await registerUser(emailC)

    const fileId = await uploadFile(userA.token, userA.masterKeyB64, 'private content')

    const res = await request(app)
      .get(`/api/files/${fileId}/download`)
      .set('Authorization', `Bearer ${userC.token}`)
      .set('X-Master-Key', userC.masterKeyB64)

    expect(res.status).toBe(403)
  })

  it('unauthenticated request (no JWT) is rejected with 401', async () => {
    const emailA = uniqueEmail()
    const userA = await registerUser(emailA)
    const fileId = await uploadFile(userA.token, userA.masterKeyB64, 'data')

    const res = await request(app)
      .get(`/api/files/${fileId}/download`)
      .set('X-Master-Key', userA.masterKeyB64)
    // No Authorization header

    expect(res.status).toBe(401)
  })

  it('file owner cannot be impersonated by sending their email', async () => {
    const emailA = uniqueEmail()
    const emailB = uniqueEmail()

    const userA = await registerUser(emailA)
    const userB = await registerUser(emailB)

    const fileId = await uploadFile(userA.token, userA.masterKeyB64, 'private')

    // User B tries to download with User B's own master key (different ECDH key)
    // The file key was wrapped for User A — User B's master key cannot unwrap it
    const res = await request(app)
      .get(`/api/files/${fileId}/download`)
      .set('Authorization', `Bearer ${userB.token}`)
      .set('X-Master-Key', userB.masterKeyB64)

    expect(res.status).toBe(403)
  })
})
