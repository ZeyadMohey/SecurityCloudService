/**
 * Shared Prisma client + cleanup helpers for integration tests.
 *
 * Uses DATABASE_URL (set by jest.setup.ts) so it connects to whichever
 * database the test suite is pointed at.
 */
import { PrismaClient } from '@prisma/client'

export const prisma = new PrismaClient()

/**
 * Delete all rows created by tests whose user email matches the given prefix.
 * Must be called in afterAll() to avoid FK constraint errors.
 *
 * Deletion order respects FK constraints:
 *   SharedFile → File → User
 */
export async function cleanupTestUsers(emailPrefix: string): Promise<void> {
  const users = await prisma.user.findMany({
    where: { email: { startsWith: emailPrefix } },
    select: { id: true },
  })
  const ids = users.map((u: { id: string }) => u.id)
  if (ids.length === 0) return

  await prisma.sharedFile.deleteMany({
    where: { OR: [{ sharedById: { in: ids } }, { sharedWithId: { in: ids } }] },
  })
  await prisma.file.deleteMany({ where: { ownerId: { in: ids } } })
  await prisma.user.deleteMany({ where: { id: { in: ids } } })
}

export async function disconnectDb(): Promise<void> {
  await prisma.$disconnect()
}
