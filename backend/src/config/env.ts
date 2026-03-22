import path from 'path'
import {
  DATABASE_URL,
  JWT_SECRET,
  MASTER_ENCRYPTION_KEY,
  ML_SERVICE_URL,
} from './secrets'

export const config = {
  port: parseInt(process.env['PORT'] ?? '3001', 10),
  nodeEnv: process.env['NODE_ENV'] ?? 'development',
  databaseUrl: DATABASE_URL,
  jwtSecret: JWT_SECRET,
  masterEncryptionKey: MASTER_ENCRYPTION_KEY,
  mlServiceUrl: ML_SERVICE_URL,
  uploadDir: path.resolve(process.env['UPLOAD_DIR'] ?? './uploads'),
}
