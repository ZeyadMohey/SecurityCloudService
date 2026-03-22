/**
 * Secrets loader — Paper [15] (Sinan et al., DevSecOps)
 *
 * In production (Docker): secrets are mounted as files at /run/secrets/<name>.
 * In development: secrets fall back to environment variables from .env.
 *
 * This indirection ensures that sensitive values are never baked into the image,
 * never passed as env vars in production, and never logged by Docker.
 */
import fs from 'fs'

function loadSecret(dockerSecretName: string, envVarName: string): string {
  // Docker Secrets path (production)
  const secretPath = `/run/secrets/${dockerSecretName}`
  try {
    if (fs.existsSync(secretPath)) {
      return fs.readFileSync(secretPath, 'utf-8').trim()
    }
  } catch {
    // Not in Docker — fall through to env var
  }

  // Environment variable (development)
  const value = process.env[envVarName]
  if (!value) {
    throw new Error(
      `Missing secret: set env var "${envVarName}" or Docker secret "${dockerSecretName}"`
    )
  }
  return value
}

// ── Secrets — Docker Secrets in prod, env vars in dev ──────────────────────
export const JWT_SECRET: string = loadSecret('jwt_secret', 'JWT_SECRET')
export const MASTER_ENCRYPTION_KEY: string = loadSecret('master_key', 'MASTER_ENCRYPTION_KEY')

// ── DATABASE_URL ────────────────────────────────────────────────────────────
// In production, the DB password comes from the db_password Docker Secret so
// it never appears in an environment variable or `docker inspect` output.
// Construction: read the host/db from DATABASE_URL env (non-sensitive) and
// substitute the secret password.
//
// Dev: DATABASE_URL env var contains the full connection string (including
// the dev password) — no Docker Secret involved.
function buildDatabaseUrl(): string {
  const envUrl = process.env['DATABASE_URL']

  // Check if a db_password Docker Secret is available (production)
  const secretPath = '/run/secrets/db_password'
  let dbPassword: string | null = null
  try {
    if (fs.existsSync(secretPath)) {
      dbPassword = fs.readFileSync(secretPath, 'utf-8').trim()
    }
  } catch {
    // Fall through
  }

  if (dbPassword && envUrl) {
    // Replace the password placeholder in DATABASE_URL.
    // The prod compose sets DATABASE_URL with __DB_PASSWORD__ as placeholder.
    return envUrl.replace('__DB_PASSWORD__', dbPassword)
  }

  // Development: use DATABASE_URL as-is (contains dev password)
  if (envUrl) return envUrl

  throw new Error('Missing DATABASE_URL environment variable')
}

export const DATABASE_URL: string = buildDatabaseUrl()

// Non-secret config
export const ML_SERVICE_URL: string =
  process.env['ML_SERVICE_URL'] ?? 'http://localhost:8000'
