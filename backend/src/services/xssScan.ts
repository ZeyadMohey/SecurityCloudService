/**
 * XSS scanning service — calls the ML microservice (Papers [3], [4]).
 *
 * Fire-and-forget: updates the DB record asynchronously after upload.
 * Never blocks the upload response; failures are logged but not propagated.
 */

import { PrismaClient } from '@prisma/client'
import { config } from '../config/env'

const prisma = new PrismaClient()

export function triggerXssScan(fileId: string, filename: string): void {
  const body = JSON.stringify({ text: filename })
  fetch(`${config.mlServiceUrl}/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body,
    signal: AbortSignal.timeout(5000),
  })
    .then((r) => r.json())
    .then((result: unknown) => {
      const scan = result as { is_xss?: boolean; confidence?: number }
      return prisma.file.update({
        where: { id: fileId },
        data: {
          xssScanStatus: scan.is_xss ? 'flagged' : 'clean',
          xssScanScore: scan.confidence ?? null,
        },
      })
    })
    .catch((err: unknown) => {
      console.error(`[XSS scan] file=${fileId} err=${err instanceof Error ? err.message : String(err)}`)
    })
}
