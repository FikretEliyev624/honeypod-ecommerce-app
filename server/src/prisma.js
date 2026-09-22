// The SINGLE Prisma client instance. Every module must import this one.
// Kept on globalThis so `node --watch` restarts do not open a new connection each time.
import { PrismaClient } from '@prisma/client';

const globalForPrisma = globalThis;

export const prisma =
  globalForPrisma.__honeypodPrisma ??
  new PrismaClient({
    log: ['warn', 'error'],
  });

globalForPrisma.__honeypodPrisma = prisma;

export default prisma;
