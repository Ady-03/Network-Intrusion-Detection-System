// ─────────────────────────────────────────────────────────────────────────────
//  NIDS — Graph Analysis Tests
//  server/graphAnalysis.test.js
//  Run: node graphAnalysis.test.js
// ─────────────────────────────────────────────────────────────────────────────

const { betweennessCentrality, unionFind, analyseGraph } = require('./graphAnalysis');

let passed = 0, failed = 0;

function assert(condition, label) {
  if (condition) { console.log(`  ✓  ${label}`); passed++; }
  else           { console.error(`  ✗  ${label}`); failed++; }
}

// ─────────────────────────────────────────────────────────────────────────────
//  TEST GRAPH
//
//  FW-1 ── RTR-1 ── SRV-1
//             |
//           RTR-2
//             |
//           PC-1
//
//  RTR-1 is the critical hub — all paths between FW-1/SRV-1 and RTR-2/PC-1
//  must go through it, so it should have the highest centrality score.
// ─────────────────────────────────────────────────────────────────────────────

const nodes = [
  { id: 'N1', label: 'FW-1',  ip: '10.0.0.1',     type: 'FIREWALL' },
  { id: 'N2', label: 'RTR-1', ip: '192.168.0.1',  type: 'ROUTER'   },
  { id: 'N3', label: 'SRV-1', ip: '192.168.0.10', type: 'SERVER'   },
  { id: 'N4', label: 'RTR-2', ip: '192.168.1.1',  type: 'ROUTER'   },
  { id: 'N5', label: 'PC-1',  ip: '192.168.0.20', type: 'PC'       },
];

const edges = [
  { id: 'E1', source: 'N1', target: 'N2', suspicious: false },
  { id: 'E2', source: 'N2', target: 'N3', suspicious: false },
  { id: 'E3', source: 'N2', target: 'N4', suspicious: false },
  { id: 'E4', source: 'N4', target: 'N5', suspicious: false },
];

// ─────────────────────────────────────────────────────────────────────────────
//  1. Betweenness Centrality
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n── Betweenness Centrality ───────────────────────────────');

const scores = betweennessCentrality(nodes, edges);

assert(scores instanceof Map,                         'Returns a Map');
assert(scores.size === nodes.length,                  'Has score for every node');
assert(scores.get('N2') === 1.0,                      'RTR-1 has max score (1.0)');
assert(scores.get('N1') === 0,                        'FW-1 has score 0 (leaf node)');
assert(scores.get('N3') === 0,                        'SRV-1 has score 0 (leaf node)');
assert(scores.get('N4') > 0,                          'RTR-2 has some centrality');
assert(scores.get('N2') >= scores.get('N4'),          'RTR-1 score >= RTR-2 score');

console.log('  Scores:', Object.fromEntries(scores));

// ─────────────────────────────────────────────────────────────────────────────
//  2. Union-Find — connectivity clusters
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n── Union-Find ───────────────────────────────────────────');

const ufResult = unionFind(nodes, edges);

assert(ufResult.totalClusters === 1,                  'All nodes in one cluster (connected graph)');
assert(ufResult.isNetworkConnected === true,           'Network is connected');
assert(ufResult.quarantine.length === 0,               'No quarantine when no compromise');

// Disconnected graph
const isolated = [...nodes, { id: 'N6', label: 'PC-2', ip: '10.10.0.5', type: 'PC' }];
const ufDisconnected = unionFind(isolated, edges);
assert(ufDisconnected.totalClusters === 2,             'Two clusters when node is isolated');
assert(ufDisconnected.isNetworkConnected === false,    'Network not connected');

// ─────────────────────────────────────────────────────────────────────────────
//  3. Union-Find — quarantine on compromise
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n── Union-Find Quarantine ────────────────────────────────');

// Compromise RTR-1 (N2) — all nodes are reachable through it so all 5 get quarantined
const ufCompromised = unionFind(nodes, edges, 'N2');
assert(ufCompromised.quarantine.includes('N2'),        'Compromised node in quarantine');
assert(ufCompromised.quarantine.includes('N1'),        'FW-1 in quarantine (connected to RTR-1)');
assert(ufCompromised.quarantine.includes('N5'),        'PC-1 in quarantine (reachable via RTR-2)');
assert(ufCompromised.compromisedClusterSize === 5,     'All 5 nodes quarantined');

// Compromise a leaf node — only its cluster gets quarantined
const ufLeaf = unionFind(nodes, edges, 'N5');
assert(ufLeaf.quarantine.includes('N5'),               'PC-1 in its own quarantine cluster');
assert(ufLeaf.compromisedClusterSize === 5,            'Whole connected graph quarantined from PC-1');

// ─────────────────────────────────────────────────────────────────────────────
//  4. analyseGraph — full pipeline
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n── analyseGraph ─────────────────────────────────────────');

const analysis = analyseGraph(nodes, edges, 'N2');

assert(!analysis.error,                                'No error on valid input');
assert(analysis.highestRiskNode.id === 'N2',           'RTR-1 identified as highest risk node');
assert(analysis.highestRiskScore === 1.0,              'Highest risk score is 1.0');
assert(Array.isArray(analysis.nodeAnalysis),           'nodeAnalysis is array');
assert(analysis.nodeAnalysis.length === nodes.length,  'One entry per node');

const rtr1Analysis = analysis.nodeAnalysis.find(n => n.id === 'N2');
assert(rtr1Analysis.isHighestRisk === true,            'RTR-1 flagged as highest risk');
assert(rtr1Analysis.isCompromised === true,            'RTR-1 flagged as compromised');
assert(rtr1Analysis.isInQuarantine === true,           'RTR-1 in quarantine');
assert(rtr1Analysis.radiusMultiplier === 2.0,          'RTR-1 radius multiplier = 2.0 (max)');

const fw1Analysis = analysis.nodeAnalysis.find(n => n.id === 'N1');
assert(fw1Analysis.isHighestRisk === false,            'FW-1 not highest risk');
assert(fw1Analysis.radiusMultiplier === 1.0,           'FW-1 radius multiplier = 1.0 (min)');

// Error case
const emptyResult = analyseGraph([], [], null);
assert(!!emptyResult.error,                            'Empty nodes returns error');

// ─────────────────────────────────────────────────────────────────────────────
//  RESULTS
// ─────────────────────────────────────────────────────────────────────────────
console.log(`\n─────────────────────────────────────────────────────────`);
console.log(`  ${passed} passed  |  ${failed} failed`);
if (failed === 0) console.log('  All tests passed — graphAnalysis.js is ready.\n');
else { console.log('  Fix failures before wiring to server.\n'); process.exit(1); }
