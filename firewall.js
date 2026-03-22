// ─────────────────────────────────────────────────────────────────────────────
//  NIDS — Firewall Rules Routes
//  server/firewall.js
//
//  POST   /api/firewall/rule        → add a block rule
//  DELETE /api/firewall/rule/:id    → remove a rule
//  GET    /api/firewall/rules       → list all active rules
//
//  Rules are stored in MySQL via Prisma.
//  BFS respects rules — blocked src→dst pairs are skipped in pathfinding.
// ─────────────────────────────────────────────────────────────────────────────

const express          = require('express');
const router           = express.Router();
const { PrismaClient } = require('@prisma/client');
const prisma           = new PrismaClient();

// ── GET /api/firewall/rules ───────────────────────────────
// Returns all active firewall rules
router.get('/rules', async (req, res) => {
  try {
    const rules = await prisma.firewallRule.findMany({
      orderBy: { createdAt: 'desc' },
    });
    return res.json(rules);
  } catch (err) {
    console.error('Firewall list error:', err);
    return res.status(500).json({ error: 'Failed to fetch rules' });
  }
});

// ── POST /api/firewall/rule ───────────────────────────────
// Add a new block rule
// Body: { srcIp, dstIp, protocol?, description? }
router.post('/rule', async (req, res) => {
  const { srcIp, dstIp, protocol = 'ANY', description = '' } = req.body;

  if (!srcIp || !dstIp) {
    return res.status(400).json({ error: 'srcIp and dstIp are required' });
  }

  try {
    const rule = await prisma.firewallRule.create({
      data: { srcIp, dstIp, protocol, description, action: 'BLOCK' },
    });
    return res.json({ message: 'Rule added', rule });
  } catch (err) {
    console.error('Firewall create error:', err);
    return res.status(500).json({ error: 'Failed to create rule' });
  }
});

// ── DELETE /api/firewall/rule/:id ─────────────────────────
// Remove a rule by id
router.delete('/rule/:id', async (req, res) => {
  const id = parseInt(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid rule id' });

  try {
    await prisma.firewallRule.delete({ where: { id } });
    return res.json({ message: `Rule ${id} deleted` });
  } catch (err) {
    console.error('Firewall delete error:', err);
    return res.status(500).json({ error: 'Failed to delete rule' });
  }
});

module.exports = router;
