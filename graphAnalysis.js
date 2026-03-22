// ─────────────────────────────────────────────────────────────────────────────
//  NIDS — Graph Analysis Module
//  server/graphAnalysis.js
//
//  Exports:
//    betweennessCentrality(nodes, edges)   → Map<nodeId, score>
//    unionFind(nodes, edges, compromisedId) → { clusters, quarantine }
//    analyseGraph(nodes, edges, compromisedId?) → full analysis object
// ─────────────────────────────────────────────────────────────────────────────

const { bfs } = require('./pathfinding');

// ─────────────────────────────────────────────────────────────────────────────
//  BETWEENNESS CENTRALITY
//
//  For every pair of nodes (s, t), find the BFS shortest path.
//  Count how many of those paths pass through each intermediate node.
//  A node with a high score sits on many shortest paths — it is the
//  most critical junction in the network and the biggest attack target.
//
//  Formula:  BC(v) = Σ (shortest paths through v) / (total shortest paths)
//
//  time:  O(V² × (V + E))  — runs BFS once per source node
//  space: O(V)
//
//  Returns: Map<nodeId, normalizedScore>  where score is 0.0 → 1.0
// ─────────────────────────────────────────────────────────────────────────────
function betweennessCentrality(nodes, edges) {
  const scores = new Map();
  nodes.forEach(n => scores.set(n.id, 0));

  if (nodes.length < 3) return scores; // need at least 3 nodes for centrality

  // For every ordered pair (src, dst), find BFS path and credit intermediates
  for (let i = 0; i < nodes.length; i++) {
    for (let j = 0; j < nodes.length; j++) {
      if (i === j) continue;

      const path = bfs(nodes, edges, nodes[i].id, nodes[j].id);
      if (!path || path.length < 3) continue;

      // Credit every intermediate node (not src, not dst)
      const intermediates = path.slice(1, -1);
      for (const node of intermediates) {
        scores.set(node.id, (scores.get(node.id) || 0) + 1);
      }
    }
  }

  // Normalize scores to 0.0–1.0 range
  const maxScore = Math.max(...scores.values(), 1);
  for (const [id, score] of scores) {
    scores.set(id, parseFloat((score / maxScore).toFixed(3)));
  }

  return scores;
}

// ─────────────────────────────────────────────────────────────────────────────
//  UNION-FIND (Disjoint Set Union)
//
//  Groups nodes into clusters based on connectivity.
//  When a node is compromised, finds ALL nodes reachable from it
//  and marks them as the quarantine cluster.
//
//  Uses path compression and union by rank for near O(α(n)) performance.
//
//  Returns:
//    clusters   — Map<rootId, nodeId[]>  all connectivity clusters
//    quarantine — nodeId[]  nodes reachable from the compromised node
//    compromisedClusterSize — how many nodes are at risk
// ─────────────────────────────────────────────────────────────────────────────
function unionFind(nodes, edges, compromisedId = null) {
  // Initialise — each node is its own root
  const parent = new Map(nodes.map(n => [n.id, n.id]));
  const rank   = new Map(nodes.map(n => [n.id, 0]));

  // Find root with path compression
  function find(id) {
    if (parent.get(id) !== id) {
      parent.set(id, find(parent.get(id))); // path compression
    }
    return parent.get(id);
  }

  // Union two sets by rank
  function union(a, b) {
    const rootA = find(a);
    const rootB = find(b);
    if (rootA === rootB) return;

    if (rank.get(rootA) < rank.get(rootB)) {
      parent.set(rootA, rootB);
    } else if (rank.get(rootA) > rank.get(rootB)) {
      parent.set(rootB, rootA);
    } else {
      parent.set(rootB, rootA);
      rank.set(rootA, rank.get(rootA) + 1);
    }
  }

  // Union all connected nodes
  for (const edge of edges) {
    if (nodes.find(n => n.id === edge.source) &&
        nodes.find(n => n.id === edge.target)) {
      union(edge.source, edge.target);
    }
  }

  // Build clusters map: root → [all members]
  const clusters = new Map();
  for (const node of nodes) {
    const root = find(node.id);
    if (!clusters.has(root)) clusters.set(root, []);
    clusters.get(root).push(node.id);
  }

  // Find quarantine cluster (nodes reachable from compromised node)
  let quarantine = [];
  let compromisedClusterSize = 0;

  if (compromisedId) {
    const compromisedRoot = find(compromisedId);
    quarantine = clusters.get(compromisedRoot) || [];
    compromisedClusterSize = quarantine.length;
  }

  return {
    clusters:              Object.fromEntries(clusters),
    quarantine,
    compromisedClusterSize,
    totalClusters:         clusters.size,
    isNetworkConnected:    clusters.size === 1,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
//  ANALYSE GRAPH — full pipeline, one call
//
//  Runs both betweenness centrality and Union-Find together.
//  Returns a single object the frontend uses to:
//    - Scale node circle sizes by centrality score
//    - Highlight the quarantine cluster in red
//    - Show the highest-risk node in the info panel
// ─────────────────────────────────────────────────────────────────────────────
function analyseGraph(nodes, edges, compromisedId = null) {
  if (nodes.length === 0) {
    return { error: 'No nodes to analyse' };
  }

  const centralityScores = betweennessCentrality(nodes, edges);
  const unionFindResult  = unionFind(nodes, edges, compromisedId);

  // Find the highest-risk node (highest centrality score)
  let highestRiskNode = null;
  let highestScore    = -1;
  for (const [nodeId, score] of centralityScores) {
    if (score > highestScore) {
      highestScore    = score;
      highestRiskNode = nodes.find(n => n.id === nodeId);
    }
  }

  // Build per-node result array for easy frontend consumption
  const nodeAnalysis = nodes.map(n => ({
    id:               n.id,
    label:            n.label,
    centralityScore:  centralityScores.get(n.id) || 0,
    isHighestRisk:    n.id === highestRiskNode?.id,
    isCompromised:    n.id === compromisedId,
    isInQuarantine:   unionFindResult.quarantine.includes(n.id),
    // radius multiplier: 1.0 normal → 2.0 highest risk
    radiusMultiplier: 1 + (centralityScores.get(n.id) || 0),
  }));

  return {
    nodeAnalysis,
    highestRiskNode,
    highestRiskScore:   highestScore,
    centrality:         Object.fromEntries(centralityScores),
    unionFind:          unionFindResult,
    compromisedId,
    timestamp:          new Date().toISOString(),
  };
}

module.exports = { betweennessCentrality, unionFind, analyseGraph };
