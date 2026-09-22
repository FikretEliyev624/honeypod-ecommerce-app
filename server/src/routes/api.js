// DAXİLİ dashboard API-si. Bu router internetə açılmamalıdır.
import express from 'express';
import { prisma } from '../prisma.js';

const router = express.Router();

// groupBy nəticəsini sadə {value, count} siyahısına çevirib çoxdan aza sıralayır.
function toCounts(rows, field, take = 0) {
  const list = rows
    .map((row) => ({ value: row[field] ?? 'unknown', count: row._count._all }))
    .sort((a, b) => b.count - a.count);
  return take > 0 ? list.slice(0, take) : list;
}

// GET /api/stats — ümumi mənzərə
router.get('/api/stats', async (req, res, next) => {
  try {
    const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000);

    const [
      totalEvents,
      unanalyzed,
      last24h,
      ipRows,
      pathRows,
      attackTypeRows,
      severityRows,
      routeRows,
      totalReports,
    ] = await Promise.all([
      prisma.honeypotEvent.count(),
      prisma.honeypotEvent.count({ where: { analyzed: false } }),
      prisma.honeypotEvent.count({ where: { createdAt: { gte: since24h } } }),
      prisma.honeypotEvent.groupBy({ by: ['ip'], _count: { _all: true } }),
      prisma.honeypotEvent.groupBy({ by: ['path'], _count: { _all: true } }),
      prisma.honeypotEvent.groupBy({
        by: ['attackType'],
        where: { analyzed: true },
        _count: { _all: true },
      }),
      prisma.honeypotEvent.groupBy({
        by: ['severity'],
        where: { analyzed: true },
        _count: { _all: true },
      }),
      prisma.honeypotEvent.groupBy({ by: ['route'], _count: { _all: true } }),
      prisma.report.count(),
    ]);

    const attackTypes = toCounts(attackTypeRows, 'attackType');

    res.json({
      totalEvents,
      uniqueIps: ipRows.length,
      // Sorğular paralel getdiyi üçün canlı trafik zamanı saylar bir-birindən
      // bir neçə hadisə geri qala bilər — mənfi dəyər göstərməmək üçün clamp.
      analyzedEvents: Math.max(totalEvents - unanalyzed, 0),
      unanalyzedEvents: unanalyzed,
      last24hEvents: last24h,
      totalReports,
      topAttackType: attackTypes[0]?.value ?? null,
      topIps: toCounts(ipRows, 'ip', 10),
      topPaths: toCounts(pathRows, 'path', 10),
      attackTypes,
      severities: toCounts(severityRows, 'severity'),
      routes: toCounts(routeRows, 'route'),
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/events?limit=&offset=&attackType=&severity=&ip=
router.get('/api/events', async (req, res, next) => {
  try {
    const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 500);
    const offset = Math.max(Number(req.query.offset) || 0, 0);

    const where = {};
    if (req.query.attackType) where.attackType = String(req.query.attackType);
    if (req.query.severity) where.severity = String(req.query.severity);
    if (req.query.ip) where.ip = String(req.query.ip);

    const [total, events] = await Promise.all([
      prisma.honeypotEvent.count({ where }),
      prisma.honeypotEvent.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip: offset,
        take: limit,
      }),
    ]);

    res.json({ total, limit, offset, events });
  } catch (err) {
    next(err);
  }
});

// GET /api/reports — ən yenidən köhnəyə
router.get('/api/reports', async (req, res, next) => {
  try {
    const limit = Math.min(Math.max(Number(req.query.limit) || 20, 1), 100);
    const reports = await prisma.report.findMany({
      orderBy: { createdAt: 'desc' },
      take: limit,
    });
    res.json({ reports });
  } catch (err) {
    next(err);
  }
});

export default router;
