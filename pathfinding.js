// ─────────────────────────────────────────────────────────────────────────────
//  NIDS — Pathfinding & Anomaly Detection Module
//  server/pathfinding.js
//
//  Exports:
//    bfs(nodes, edges, srcId, dstId)          → node[] | null
//    evasivePath(nodes, edges, srcId, dstId)  → node[] | null
//    detectAnomaly(actualPath, bfsPath)        → AnomalyResult
//    analysePacket(nodes, edges, srcId, dstId, hostile) → FullAnalysis
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
//  HELPER — build adjacency map from edges array
//
//  edges look like: { id, source: nodeId, target: nodeId, suspicious, blocked }
//  Returns: Map<nodeId, nodeId[]>
// ─────────────────────────────────────────────────────────────────────────────
function buildAdjacency(nodes, edges, blockedEdgeIds = new Set()) {
  const adj = new Map();

  // Initialise every node with an empty neighbour list
  for (const node of nodes) {
    adj.set(node.id, []);
  }

  for (const edge of edges) {
    // Skip edges explicitly blocked (firewall rules will use this in Week 4)
    if (blockedEdgeIds.has(edge.id)) continue;

    const srcList = adj.get(edge.source);
    const dstList = adj.get(edge.target);

    // Undirected graph — add both directions
    if (srcList) srcList.push(edge.target);
    if (dstList) dstList.push(edge.source);
  }

  return adj;
}

// ─────────────────────────────────────────────────────────────────────────────
//  HELPER — reconstruct path from BFS parent map
//
//  parent: Map<nodeId, nodeId | null>   (null means it's the source)
//  nodeMap: Map<nodeId, node>
//  Returns the path as an array of node objects, src → dst
// ─────────────────────────────────────────────────────────────────────────────
function reconstructPath(parent, nodeMap, srcId, dstId) {
  const path = [];
  let current = dstId;

  // Walk parent pointers from dst back to src
  while (current !== null) {
    const node = nodeMap.get(current);
    if (!node) return null; // Corrupt state — shouldn't happen
    path.unshift(node);     // Prepend so path goes src → dst
    current = parent.get(current);
  }

  // Sanity check: first node must be src
  if (path.length === 0 || path[0].id !== srcId) return null;

  return path;
}

// ─────────────────────────────────────────────────────────────────────────────
//  BFS — TRUE SHORTEST PATH
//
//  Standard breadth-first search. Guarantees the minimum number of hops
//  between srcId and dstId on an unweighted graph.
//
//  params:
//    nodes          — array of node objects ({ id, label, ip, type, x, y })
//    edges          — array of edge objects ({ id, source, target, ... })
//    srcId          — id of the source node
//    dstId          — id of the destination node
//    blockedEdgeIds — Set of edge ids to treat as removed (for firewall rules)
//
//  returns: array of node objects [src, ...intermediates, dst]
//           or null if no path exists (disconnected graph)
//
//  time:  O(V + E)
//  space: O(V)
// ─────────────────────────────────────────────────────────────────────────────
function bfs(nodes, edges, srcId, dstId, blockedEdgeIds = new Set()) {
  // Edge case: same node
  if (srcId === dstId) {
    const node = nodes.find(n => n.id === srcId);
    return node ? [node] : null;
  }

  const adj     = buildAdjacency(nodes, edges, blockedEdgeIds);
  const nodeMap = new Map(nodes.map(n => [n.id, n]));

  // parent[id] = the node we came from (null for source)
  const parent  = new Map([[srcId, null]]);
  const visited = new Set([srcId]);
  const queue   = [srcId];           // Simple FIFO queue

  while (queue.length > 0) {
    const current = queue.shift();   // Dequeue front

    // Early exit — we found the destination
    if (current === dstId) {
      return reconstructPath(parent, nodeMap, srcId, dstId);
    }

    // Enqueue all unvisited neighbours
    const neighbours = adj.get(current) || [];
    for (const neighbourId of neighbours) {
      if (!visited.has(neighbourId)) {
        visited.add(neighbourId);
        parent.set(neighbourId, current);
        queue.push(neighbourId);
      }
    }
  }

  // Queue exhausted without reaching dst — graph is disconnected
  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
//  EVASIVE PATH — attacker's detour route
//
//  An attacker trying to avoid detection doesn't travel the obvious shortest
//  path — they route through unexpected intermediate nodes to evade signature-
//  based detection that watches the "normal" traffic path.
//
//  Strategy:
//    1. Find the BFS shortest path (the "normal" route).
//    2. Extract the intermediate nodes on that path (not src, not dst).
//    3. Re-run BFS with those intermediate nodes treated as blocked.
//    4. The result is forced through different nodes → longer hop count.
//    5. If no detour exists, fall back to the BFS path (attacker has no choice).
//
//  Why this matters for anomaly detection:
//    If actual hops > BFS hops, the packet took a suspicious route — flag it.
//
//  returns: array of node objects, or null if graph has no path at all
// ─────────────────────────────────────────────────────────────────────────────
function evasivePath(nodes, edges, srcId, dstId) {
  // Step 1 — find the optimal path first
  const optimalPath = bfs(nodes, edges, srcId, dstId);
  if (!optimalPath || optimalPath.length < 2) return optimalPath;

  // Step 2 — collect intermediate node ids (strip src and dst)
  const intermediateIds = new Set(
    optimalPath.slice(1, -1).map(n => n.id)
  );

  // If the optimal path is direct (no intermediates), there's nothing to evade
  if (intermediateIds.size === 0) return optimalPath;

  // Step 3 — build a modified adjacency map that skips edges touching
  //           intermediate nodes (except edges from src or to dst)
  //
  //  We can't just "delete" nodes from the graph, so we collect edge ids
  //  whose source or target is an intermediate node to block them.
  const blockedEdgeIds = new Set();
  for (const edge of edges) {
    const srcIsIntermediate = intermediateIds.has(edge.source) && edge.source !== srcId && edge.source !== dstId;
    const dstIsIntermediate = intermediateIds.has(edge.target) && edge.target !== srcId && edge.target !== dstId;
    if (srcIsIntermediate || dstIsIntermediate) {
      blockedEdgeIds.add(edge.id);
    }
  }

  // Step 4 — run BFS on the modified graph
  const detourPath = bfs(nodes, edges, srcId, dstId, blockedEdgeIds);

  // Step 5 — if no detour found, attacker is forced onto the optimal path
  if (!detourPath) return optimalPath;

  return detourPath;
}

// ─────────────────────────────────────────────────────────────────────────────
//  DETECT ANOMALY — compare actual vs BFS shortest path
//
//  This is the core of the NIDS detection logic.
//  An anomaly is declared when the observed packet path is longer than
//  the BFS shortest path by more than the defined threshold.
//
//  params:
//    actualPath — node[] the packet actually travelled
//    bfsPath    — node[] the shortest known path (BFS result)
//    threshold  — how many extra hops are tolerated before flagging (default 1)
//                 Set to 0 to flag any deviation; 1 to allow minor variance
//
//  returns: AnomalyResult object
// ─────────────────────────────────────────────────────────────────────────────
function detectAnomaly(actualPath, bfsPath, threshold = 1) {
  const actualHops = actualPath.length - 1;
  const bfsHops    = bfsPath ? bfsPath.length - 1 : actualHops;
  const hopDelta   = actualHops - bfsHops;
  const isAnomaly  = hopDelta > threshold;

  // Severity bands
  let severity = 'none';
  if (isAnomaly) {
    if (hopDelta <= 2) severity = 'low';
    else if (hopDelta <= 4) severity = 'medium';
    else severity = 'high';
  }

  // Readable path strings for logging / UI
  const actualPathStr = actualPath.map(n => n.label).join(' → ');
  const bfsPathStr    = bfsPath ? bfsPath.map(n => n.label).join(' → ') : actualPathStr;

  return {
    isAnomaly,
    severity,          // 'none' | 'low' | 'medium' | 'high'
    actualHops,
    bfsHops,
    hopDelta,          // How many extra hops vs optimal (0 = normal)
    threshold,
    actualPathStr,
    bfsPathStr,
    message: isAnomaly
      ? `Evasive route: ${actualHops} hops vs BFS optimal ${bfsHops} (+${hopDelta})`
      : `Normal route: ${actualHops} hops (optimal)`,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
//  ANALYSE PACKET — full pipeline, one call does everything
//
//  This is what your Express route calls. It:
//    1. Picks src/dst (random if not provided)
//    2. Runs BFS to find shortest path
//    3. If hostile, runs evasivePath for the attacker detour
//    4. Runs detectAnomaly to compare
//    5. Returns a clean result object ready to emit via Socket.io
//
//  params:
//    nodes    — node array from DB / in-memory state
//    edges    — edge array
//    srcId    — source node id (optional, random if null)
//    dstId    — destination node id (optional, random if null)
//    hostile  — boolean, true = simulate attack with evasive routing
//
//  returns: FullAnalysis object
// ─────────────────────────────────────────────────────────────────────────────
function analysePacket(nodes, edges, srcId = null, dstId = null, hostile = false) {
  if (nodes.length < 2 || edges.length === 0) {
    return { error: 'Need at least 2 connected nodes' };
  }

  // Pick random src/dst if not specified
  const pickRandom = (exclude = null) => {
    const pool = exclude ? nodes.filter(n => n.id !== exclude) : nodes;
    return pool[Math.floor(Math.random() * pool.length)];
  };

  const src = srcId ? nodes.find(n => n.id === srcId) : pickRandom();
  const dst = dstId ? nodes.find(n => n.id === dstId) : pickRandom(src.id);

  if (!src || !dst) return { error: 'Invalid src/dst node ids' };

  // Always compute BFS path — this is the "normal" baseline
  const bfsPath = bfs(nodes, edges, src.id, dst.id);

  if (!bfsPath) {
    return {
      error: `No path from ${src.label} to ${dst.label} — graph may be disconnected`,
      src,
      dst,
    };
  }

  // Hostile packets take an evasive detour; normal packets follow BFS
  const actualPath = hostile
    ? evasivePath(nodes, edges, src.id, dst.id)
    : bfsPath;

  if (!actualPath) return { error: 'Could not compute path' };

  // Run anomaly detection
  const anomaly = detectAnomaly(actualPath, bfsPath);

  return {
    src,
    dst,
    hostile,
    actualPath,       // Full node array — animate this on the canvas
    bfsPath,          // Full node array — show in right panel
    anomaly,          // AnomalyResult — use for alerts + DB write
    timestamp: new Date().toISOString(),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
//  EXPORTS
// ─────────────────────────────────────────────────────────────────────────────
module.exports = { bfs, evasivePath, detectAnomaly, analysePacket };
