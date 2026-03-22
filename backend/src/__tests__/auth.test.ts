/**
 * Tests Authentication
 *
 * Requires DATABASE_URL to point to a running PostgreSQL instance.
 * Run inside Docker:  docker compose exec backend npm test
 *
 */
import request from 'supertest'
import jwt from 'jsonwebtoken'
import { cleanupTestUsers, disconnectDb } from './helpers/testDb'
import app from '../app'

// All test accounts use this prefix so cleanup is scoped
const EMAIL_PREFIX = 'jest_auth_'
const uniqueEmail = () => `${EMAIL_PREFIX}${Date.now()}_${Math.random().toString(36).slice(2)}@test.com`
const VALID_PASSWORD = 'TestPass1'

afterAll(async () => {
  await cleanupTestUsers(EMAIL_PREFIX)
  await disconnectDb()
})

describe('POST /api/auth/register', () => {
  it('creates a user and returns a JWT + ECDH public key', async () => {
    const email = uniqueEmail()
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email, password: VALID_PASSWORD })

    expect(res.status).toBe(201)
    expect(res.body).toHaveProperty('token')
    expect(res.body.user).toMatchObject({ email: email.toLowerCase() })

    // ECDH key pair
    expect(typeof res.body.user.ecdhPublicKey).toBe('string')
    expect(res.body.user.ecdhPublicKey.length).toBe(130)

    // ecdhSalt 
    expect(typeof res.body.user.ecdhSalt).toBe('string')
    expect(res.body.user.ecdhSalt.length).toBe(64) // 32 bytes hex

    // JWT verifiable
    const jwtSecret = process.env['JWT_SECRET'] ?? ''
    const payload = jwt.verify(res.body.token as string, jwtSecret) as { userId: string; email: string }
    expect(payload.email).toBe(email.toLowerCase())
  })

  it('rejects duplicate email with 409', async () => {
    const email = uniqueEmail()
    await request(app).post('/api/auth/register').send({ email, password: VALID_PASSWORD })

    const res = await request(app)
      .post('/api/auth/register')
      .send({ email, password: VALID_PASSWORD })

    expect(res.status).toBe(409)
    expect(res.body).toHaveProperty('message')
  })

  it('rejects weak password (no digit) with 400', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: uniqueEmail(), password: 'NoDigitHere' })

    expect(res.status).toBe(400)
  })

  it('rejects invalid email format with 400', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: 'not-an-email', password: VALID_PASSWORD })

    expect(res.status).toBe(400)
  })
})

describe('POST /api/auth/login', () => {
  const loginEmail = uniqueEmail()

  beforeAll(async () => {
    await request(app)
      .post('/api/auth/register')
      .send({ email: loginEmail, password: VALID_PASSWORD })
  })

  it('returns a valid JWT for correct credentials', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: loginEmail, password: VALID_PASSWORD })

    expect(res.status).toBe(200)
    expect(res.body).toHaveProperty('token')

    const jwtSecret = process.env['JWT_SECRET'] ?? ''
    const payload = jwt.verify(res.body.token as string, jwtSecret) as { userId: string; email: string }
    expect(payload.email).toBe(loginEmail.toLowerCase())

    // Login response includes ecdhSalt for master key 
    expect(typeof res.body.user.ecdhSalt).toBe('string')
  })

  it('rejects wrong password with 401', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: loginEmail, password: 'WrongPass9' })

    expect(res.status).toBe(401)
    expect(res.body.message).toBe('Invalid credentials')
  })

  it('rejects unknown email with 401 (no account enumeration)', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: uniqueEmail(), password: VALID_PASSWORD })

    expect(res.status).toBe(401)
    // Same message as wrong password timing-safe comparison prevents enumeration
    expect(res.body.message).toBe('Invalid credentials')
  })
})
