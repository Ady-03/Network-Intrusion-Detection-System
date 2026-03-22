// ─────────────────────────────────────────────────────────────────────────────
//  NIDS — Simulation Routes (Week 3 update)
//  server/simulate.js
//
//  Changes from Week 2:
//    - Now exports a function that accepts io (Socket.io instance)
//    - Saves every alert to MySQL via Prisma
//    - Emits 'alert' and 'packet' events to all connected browsers instantly
// ─────────────────────────────────────────────────────────────────────────────

const express          = require('express');
const { PrismaClient } = require('@prisma/client');
const { analysePacket } = require('./pathfinding');

const prisma = new PrismaClient();

// Export a function that takes io and returns the router
// This pattern lets routes emit Socket.io events
module.exports = function(io) {
  const router = express.Router();

  // ── Shared handler ──────────────────────────────────
  async function runSimulation(req, res, hostile) {
    const { nodes, edges, srcId = null, dstId = null, topologyId = null } = req.body;

    if (!Array.isArray(nodes) || !Array.isArray(edges)) {
      return res.status(400).json({ error: 'nodes and edges must be arrays' });
    }

    const result = analysePacket(nodes, edges, srcId, dstId, hostile);

    if (result.error) {
      return res.status(422).json(result);
    }

    // ── Save alert to MySQL ───────────────────────────
    let savedAlert = null;
    try {
      savedAlert = await prisma.alert.create({
        data: {
          type:       hostile ? 'INTRUSION' : 'INFO',
          message:    result.anomaly.message,
          severity:   result.anomaly.severity === 'none' ? 'low' : result.anomaly.severity,
          srcIp:      result.src.ip,
          dstIp:      result.dst.ip,
          topologyId: topologyId || 1,      // default to topology 1 if not provided
        },
      });
    } catch (err) {
      // Don't fail the whole request if alert save fails
      console.error('Alert save error:', err.message);
    }

    // ── Emit to all connected browsers via Socket.io ──
    const socketPayload = {
      id:          savedAlert?.id,
      type:        hostile ? 'INTRUSION' : 'INFO',
      severity:    result.anomaly.severity === 'none' ? 'low' : result.anomaly.severity,
      message:     result.anomaly.message,
      srcIp:       result.src.ip,
      dstIp:       result.dst.ip,
      srcLabel:    result.src.label,
      dstLabel:    result.dst.label,
      isAnomaly:   result.anomaly.isAnomaly,
      actualHops:  result.anomaly.actualHops,
      bfsHops:     result.anomaly.bfsHops,
      actualPath:  result.actualPath.map(n => n.label),
      bfsPath:     result.bfsPath.map(n => n.label),
      timestamp:   new Date().toISOString(),
    };

    io.emit('alert', socketPayload);        // every connected browser gets this
    io.emit('packet', {                     // separate event for canvas animation
      hostile,
      path: result.actualPath,
    });

    return res.json({ ...result, savedAlert });
  }

  // ── Routes ──────────────────────────────────────────
  router.post('/packet', (req, res) => runSimulation(req, res, false));
  router.post('/attack', (req, res) => runSimulation(req, res, true));

  return router;
};
