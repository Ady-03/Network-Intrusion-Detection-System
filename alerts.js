// ─────────────────────────────────────────────────────────────────────────────
//  NIDS — Alerts Routes
//  server/alerts.js
//
//  GET  /api/alerts          → last 50 alerts from MySQL
//  GET  /api/alerts/stats    → total counts by severity
//  DELETE /api/alerts        → clear all alerts (useful for testing)
// ─────────────────────────────────────────────────────────────────────────────

const express          = require('express');
const router           = express.Router();
const { PrismaClient } = require('@prisma/client');
const prisma           = new PrismaClient();

// ── GET /api/alerts ───────────────────────────────────
// Returns last 50 alerts ordered newest first.
// Frontend calls this on mount to pre-populate the alert feed
// before live Socket.io events start coming in.
router.get('/', async (req, res) => {
  try {
    const alerts = await prisma.alert.findMany({
      orderBy: { createdAt: 'desc' },
      take:    50,
      select: {
        id:        true,
        type:      true,
        message:   true,
        severity:  true,
        srcIp:     true,
        dstIp:     true,
        createdAt: true,
      },
    });

    return res.json(alerts);

  } catch (err) {
    console.error('Alerts fetch error:', err);
    return res.status(500).json({ error: 'Failed to fetch alerts' });
  }
});

// ── GET /api/alerts/stats ─────────────────────────────
// Returns counts grouped by severity — useful for the dashboard.
router.get('/stats', async (req, res) => {
  try {
    const stats = await prisma.alert.groupBy({
      by:     ['severity'],
      _count: { severity: true },
    });

    // Reshape into a clean object: { low: 5, medium: 2, high: 1 }
    const counts = { low: 0, medium: 0, high: 0 };
    for (const row of stats) {
      counts[row.severity] = row._count.severity;
    }
    counts.total = counts.low + counts.medium + counts.high;

    return res.json(counts);

  } catch (err) {
    console.error('Stats error:', err);
    return res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// ── DELETE /api/alerts ────────────────────────────────
// Clears all alerts — handy during development/testing.
router.delete('/', async (req, res) => {
  try {
    const { count } = await prisma.alert.deleteMany({});
    return res.json({ message: `Deleted ${count} alerts` });
  } catch (err) {
    console.error('Delete error:', err);
    return res.status(500).json({ error: 'Failed to delete alerts' });
  }
});

module.exports = router;
