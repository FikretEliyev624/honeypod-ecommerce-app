// Prisma client-in TƏK nüsxəsi. Bütün modullar bunu import etməlidir.
// `node --watch` restart edəndə təkrar bağlantı yaranmasın deyə globalThis-də saxlanılır.
import { PrismaClient } from '@prisma/client';

const globalForPrisma = globalThis;

export const prisma =
  globalForPrisma.__honeypodPrisma ??
  new PrismaClient({
    log: ['warn', 'error'],
  });

globalForPrisma.__honeypodPrisma = prisma;

export default prisma;
