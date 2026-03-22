// ─────────────────────────────────────────────────────────────────────────────
//  NIDS — Topology Routes
//  server/topology.js
//
//  POST /api/network/save        → save canvas nodes + edges to MySQL
//  GET  /api/network/:id         → load topology from MySQL by id
//  GET  /api/network             → list all saved topologies
// ─────────────────────────────────────────────────────────────────────────────

const express      = require('express');
const router       = express.Router();
const { PrismaClient } = require('@prisma/client');
const prisma       = new PrismaClient();

// ─────────────────────────────────────────────────────────────────────────────
//  POST /api/network/save
//  Body: { name, nodes, edges }
//  Saves the entire canvas state to MySQL.
//  Returns the saved topology with its new DB id.
// ─────────────────────────────────────────────────────────────────────────────
router.post('/save', async (req, res) => {
  const { name = 'My Network', nodes = [], edges = [] } = req.body;

  if (!Array.isArray(nodes) || !Array.isArray(edges)) {
    return res.status(400).json({ error: 'nodes and edges must be arrays' });
  }

  try {
    // Create topology + all nodes + all edges in one transaction
    const topology = await prisma.topology.create({
      data: {
        name,
        nodes: {
          create: nodes.map(n => ({
            nodeId: n.id,
            label:  n.label,
            ip:     n.ip,
            type:   n.type,
            x:      n.x,
            y:      n.y,
          })),
        },
        edges: {
          create: edges.map(e => ({
            edgeId:     e.id,
            source:     e.source,
            target:     e.target,
            suspicious: e.suspicious || false,
          })),
        },
      },
      include: { nodes: true, edges: true },
    });

    return res.json({
      message:    'Topology saved successfully',
      topologyId: topology.id,
      name:       topology.name,
      nodeCount:  topology.nodes.length,
      edgeCount:  topology.edges.length,
    });

  } catch (err) {
    console.error('Save error:', err);
    return res.status(500).json({ error: 'Failed to save topology' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
//  GET /api/network/:id
//  Loads a topology from MySQL and returns it in the same shape
//  the D3 canvas expects — so you can do nodes = result.nodes directly.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/:id', async (req, res) => {
  const id = parseInt(req.params.id);

  if (isNaN(id)) {
    return res.status(400).json({ error: 'Invalid topology id' });
  }

  try {
    const topology = await prisma.topology.findUnique({
      where:   { id },
      include: { nodes: true, edges: true },
    });

    if (!topology) {
      return res.status(404).json({ error: `Topology ${id} not found` });
    }

    // Reshape to match the D3 canvas format exactly
    const nodes = topology.nodes.map(n => ({
      id:    n.nodeId,
      label: n.label,
      ip:    n.ip,
      type:  n.type,
      x:     n.x,
      y:     n.y,
    }));

    const edges = topology.edges.map(e => ({
      id:         e.edgeId,
      source:     e.source,
      target:     e.target,
      suspicious: e.suspicious,
    }));

    return res.json({
      topologyId: topology.id,
      name:       topology.name,
      createdAt:  topology.createdAt,
      nodes,
      edges,
    });

  } catch (err) {
    console.error('Load error:', err);
    return res.status(500).json({ error: 'Failed to load topology' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
//  GET /api/network
//  Lists all saved topologies (id + name + createdAt only, no nodes/edges)
//  Useful for a "Load saved network" dropdown on the frontend.
// ─────────────────────────────────────────────────────────────────────────────
router.get('/', async (req, res) => {
  try {
    const topologies = await prisma.topology.findMany({
      orderBy: { createdAt: 'desc' },
      select: {
        id:        true,
        name:      true,
        createdAt: true,
        _count: {
          select: { nodes: true, edges: true }
        },
      },
    });

    return res.json(topologies);

  } catch (err) {
    console.error('List error:', err);
    return res.status(500).json({ error: 'Failed to list topologies' });
  }
});

module.exports = router;
