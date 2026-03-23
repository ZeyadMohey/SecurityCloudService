/**
 * Loads secrets from Docker Secret files (/run/secrets/<name>) in production,
 * falling back to environment variables in development.
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
    // Not in Docker   fall through to env var
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

// ── Secrets   Docker Secrets in prod, env vars in dev ──────────────────────
export const JWT_SECRET: string = loadSecret('jwt_secret', 'JWT_SECRET')
export const MASTER_ENCRYPTION_KEY: string = loadSecret('master_key', 'MASTER_ENCRYPTION_KEY')

// ── DATABASE_URL ────────────────────────────────────────────────────────────
// Production: reads db_password from Docker Secret and substitutes __DB_PASSWORD__
// in the DATABASE_URL env var. Dev: uses DATABASE_URL as-is.
function buildDatabaseUrl(): string {
  const envUrl = process.env['DATABASE_URL']

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
    // Replace the __DB_PASSWORD__ placeholder set by docker-compose.prod.yml.
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
