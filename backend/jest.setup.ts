/**
 * Jest global setup   runs in each worker before any test module is imported.
 * Sets env vars consumed by config/secrets.ts at module-load time.
 */
import os from 'os'
import path from 'path'
import fs from 'fs'

process.env['NODE_ENV'] = 'test'

// Secrets   used by config/secrets.ts when /run/secrets/* files are absent
process.env['JWT_SECRET'] ??= 'test_jwt_secret_minimum_32_characters_long_for_jest'
process.env['MASTER_ENCRYPTION_KEY'] ??= '0'.repeat(64) // 32-byte all-zero key (dev only)

// DATABASE_URL resolution order:
//  1. TEST_DATABASE_URL (explicit test DB override)
//  2. DATABASE_URL already set in the environment (Docker / CI)
//  3. Default dev URL (unit tests that never actually connect to DB still need
//     secrets.ts to load without throwing)
process.env['DATABASE_URL'] =
  process.env['TEST_DATABASE_URL'] ??
  process.env['DATABASE_URL'] ??
  'postgresql://securevault:securevault_dev_password@localhost:5433/securevault'

// Isolate file uploads to a temp directory so tests never touch ./uploads
const testUploadDir = path.join(os.tmpdir(), 'securevault-test-uploads')
fs.mkdirSync(testUploadDir, { recursive: true })
fs.mkdirSync(path.join(testUploadDir, 'tmp'), { recursive: true })
process.env['UPLOAD_DIR'] = testUploadDir

// Point ML scanner at localhost (tests mock global.fetch to avoid real calls)
process.env['ML_SERVICE_URL'] ??= 'http://localhost:8000'
