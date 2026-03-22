// ─────────────────────────────────────────────────────────────────────────────
//  NIDS — Graph Analysis Routes
//  server/analysis.js
//
//  POST /api/analysis/graph         → betweenness centrality + Union-Find
//  POST /api/analysis/compromise    → mark a node compromised, get quarantine
// ─────────────────────────────────────────────────────────────────────────────

const express            = require('express');
const router             = express.Router();
const { analyseGraph }   = require('./graphAnalysis');

// ── POST /api/analysis/graph ──────────────────────────────
// Runs betweenness centrality and Union-Find on the current topology.
// Body: { nodes, edges, compromisedId? }
router.post('/graph', (req, res) => {
  const { nodes, edges, compromisedId = null } = req.body;

  if (!Array.isArray(nodes) || !Array.isArray(edges)) {
    return res.status(400).json({ error: 'nodes and edges must be arrays' });
  }

  const result = analyseGraph(nodes, edges, compromisedId);

  if (result.error) {
    return res.status(422).json(result);
  }

  return res.json(result);
});

// ── POST /api/analysis/compromise ────────────────────────
// Mark a specific node as compromised.
// Returns the quarantine cluster — all nodes that need to be isolated.
// Body: { nodes, edges, compromisedId }
router.post('/compromise', (req, res) => {
  const { nodes, edges, compromisedId } = req.body;

  if (!compromisedId) {
    return res.status(400).json({ error: 'compromisedId is required' });
  }

  const result = analyseGraph(nodes, edges, compromisedId);

  if (result.error) {
    return res.status(422).json(result);
  }

  return res.json({
    compromisedId,
    quarantine:            result.unionFind.quarantine,
    compromisedClusterSize: result.unionFind.compromisedClusterSize,
    nodeAnalysis:          result.nodeAnalysis,
    message: `${result.unionFind.compromisedClusterSize} nodes flagged for quarantine`,
  });
});

module.exports = router;
