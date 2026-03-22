/**
 * xss-scanner.test.ts — Unit tests for the XSS scan service and middleware.
 *
 * fetch is mocked globally so no ML microservice needs to be running.
 *
 * Papers covered:
 *  [1]  Layered input defense
 *  [3]  CNN-LSTM XSS detection model
 *  [4]  Character-level tokenization
 */
import express from 'express'
import multer from 'multer'
import request from 'supertest'
import { scanText } from '../services/xss-scanner'
import { xssScanMiddleware } from '../middleware/xss-scan'

// Alias for the fetch Response type (not Express's Response)
type FetchResponse = Awaited<ReturnType<typeof fetch>>

// ── Mock helpers ──────────────────────────────────────────────────────────────

function mockFetchXss(confidence = 0.95): void {
  jest.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
    ok: true,
    json: async () => ({ is_xss: true, confidence }),
  } as unknown as FetchResponse)
}

function mockFetchBenign(confidence = 0.05): void {
  jest.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
    ok: true,
    json: async () => ({ is_xss: false, confidence }),
  } as unknown as FetchResponse)
}

function mockFetchUnavailable(): void {
  jest.spyOn(globalThis, 'fetch').mockRejectedValueOnce(
    new Error('Connection refused')
  )
}

afterEach(() => jest.restoreAllMocks())

// ── Minimal Express app for middleware tests ──────────────────────────────────

const middlewareApp = express()
middlewareApp.use(express.json())
// Memory storage — no disk I/O needed for middleware tests
middlewareApp.use(multer({ storage: multer.memoryStorage() }).single('file'))
middlewareApp.post('/scan-test', xssScanMiddleware, (req, res) => {
  res.json({ blocked: false, scanResult: req.xssScanResult })
})

// ── scanText() unit tests ─────────────────────────────────────────────────────

describe('scanText()', () => {
  it('returns ScanResult with isXss=true for a flagged payload', async () => {
    mockFetchXss(0.97)
    const result = await scanText('<script>alert(1)</script>')
    expect(result).not.toBeNull()
    expect(result?.isXss).toBe(true)
    expect(result?.confidence).toBeCloseTo(0.97)
  })

  it('returns ScanResult with isXss=false for a benign filename', async () => {
    mockFetchBenign(0.04)
    const result = await scanText('vacation_photo.jpg')
    expect(result).not.toBeNull()
    expect(result?.isXss).toBe(false)
  })

  it('returns null when ML service is unavailable (graceful degrade)', async () => {
    mockFetchUnavailable()
    const result = await scanText('test.txt')
    expect(result).toBeNull()
  })

  it('returns null when ML service returns non-200', async () => {
    jest.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok: false,
      status: 503,
    } as unknown as FetchResponse)
    const result = await scanText('test.txt')
    expect(result).toBeNull()
  })

  it('returns null on AbortError timeout', async () => {
    jest.spyOn(globalThis, 'fetch').mockImplementationOnce(() => {
      const err = new Error('The operation was aborted')
      err.name = 'AbortError'
      return Promise.reject(err)
    })
    const result = await scanText('test.txt')
    expect(result).toBeNull()
  })
})

// ── xssScanMiddleware — known XSS payloads blocked ───────────────────────────

describe('xssScanMiddleware — XSS payloads blocked (Papers [3], [4])', () => {
  const XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    'javascript:void(0)',
    // URL-encoded variant — middleware receives the raw (encoded) filename string
    '%3Cscript%3Ealert(1)%3C/script%3E',
  ]

  XSS_PAYLOADS.forEach((payload) => {
    it(`blocks payload: ${payload.slice(0, 40)}`, async () => {
      mockFetchXss(0.92)
      const res = await request(middlewareApp)
        .post('/scan-test')
        .attach('file', Buffer.from('content'), { filename: payload, contentType: 'text/plain' })

      expect(res.status).toBe(400)
      expect(res.body).toHaveProperty('error', 'Content flagged as potential XSS')
      expect(res.body.confidence).toBeGreaterThan(0.7)
    })
  })
})

// ── xssScanMiddleware — benign filenames pass ─────────────────────────────────

describe('xssScanMiddleware — benign filenames pass', () => {
  const BENIGN_NAMES = [
    'vacation_photo.jpg',
    'report-2024.pdf',
    'My Document (final).docx',
  ]

  BENIGN_NAMES.forEach((name) => {
    it(`allows: ${name}`, async () => {
      mockFetchBenign(0.03)
      const res = await request(middlewareApp)
        .post('/scan-test')
        .attach('file', Buffer.from('content'), { filename: name, contentType: 'text/plain' })

      expect(res.status).toBe(200)
      expect(res.body.blocked).toBe(false)
    })
  })
})

// ── xssScanMiddleware — ML unavailable allows upload ─────────────────────────

describe('xssScanMiddleware — graceful degrade when ML unavailable', () => {
  it('passes request through and sets xssScanResult=null when ML is down', async () => {
    mockFetchUnavailable()
    const res = await request(middlewareApp)
      .post('/scan-test')
      .attach('file', Buffer.from('content'), {
        filename: '<script>alert(1)</script>.jpg',
        contentType: 'text/plain',
      })

    // Upload is allowed (ML failure is non-fatal — async fallback scan handles it)
    expect(res.status).toBe(200)
    expect(res.body.scanResult).toBeNull()
  })
})

// ── xssScanMiddleware — confidence threshold boundary ────────────────────────

describe('xssScanMiddleware — confidence threshold (0.7)', () => {
  it('allows content with XSS confidence exactly at threshold (0.7 is NOT > 0.7)', async () => {
    jest.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok: true,
      json: async () => ({ is_xss: true, confidence: 0.7 }),
    } as unknown as FetchResponse)

    const res = await request(middlewareApp)
      .post('/scan-test')
      .attach('file', Buffer.from('content'), { filename: 'borderline.txt', contentType: 'text/plain' })

    expect(res.status).toBe(200)
  })

  it('blocks content with confidence just above threshold (0.701)', async () => {
    jest.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok: true,
      json: async () => ({ is_xss: true, confidence: 0.701 }),
    } as unknown as FetchResponse)

    const res = await request(middlewareApp)
      .post('/scan-test')
      .attach('file', Buffer.from('content'), { filename: 'overline.txt', contentType: 'text/plain' })

    expect(res.status).toBe(400)
  })
})
