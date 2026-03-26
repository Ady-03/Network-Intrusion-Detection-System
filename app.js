// socket connection
const socket = io()

socket.on('connect', () => {
  const badge = document.getElementById('connBadge')
  badge.className = 'conn-badge live'
  document.getElementById('connLabel').textContent = socket.id.slice(0, 8).toUpperCase()
  fetchFirewallRules()
})

socket.on('disconnect', () => {
  document.getElementById('connBadge').className = 'conn-badge dead'
  document.getElementById('connLabel').textContent = 'OFFLINE'
})

socket.on('welcome', d => addAlert('INFO', d.message, 'low'))

socket.on('alert:new', d => {
  addAlert(d.type, d.message, d.severity)
  if (d.type !== 'BLOCKED') {
    intrusionCount++
    document.getElementById('statIntrusions').textContent = intrusionCount
  }
})

socket.on('packet:move', d => flashNode(d.nodeId))

socket.on('firewall:updated', d => {
  drawRulesTable(d.rules)
  document.getElementById('statRules').textContent = d.rules.length
})

// tab switching
function switchTab(name) {
  document.querySelectorAll('.tab').forEach((t, i) => {
    t.classList.toggle('active', ['canvas', 'firewall', 'centrality'][i] === name)
  })
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'))
  document.getElementById('view-' + name).classList.add('active')
  if (name === 'canvas') { resize(); render() }
}

// state
let nodes = []
let edges = []
let nodeIdCounter = 0
let mode = 'add'
let nodeType = 'PC'
let cf = null // connectFirst
let selected = null
let packetCount = 0
let intrusionCount = 0
let criticalNode = null
const alertLog = []

// node appearance config
const NODE_CFG = {
  PC:       { fill: '#dbeafe', stroke: '#0ea5e9', icon: '💻' },
  SERVER:   { fill: '#ede9fe', stroke: '#7c3aed', icon: '🖥' },
  ROUTER:   { fill: '#dcfce7', stroke: '#10b981', icon: '📡' },
  FIREWALL: { fill: '#ffedd5', stroke: '#f97316', icon: '🛡' },
}

// d3 canvas setup
const svg = d3.select('#canvas')
let W = 0, H = 0

function resize() {
  const el = document.querySelector('.canvas-wrap')
  if (!el) return
  W = el.clientWidth
  H = el.clientHeight
  svg.attr('width', W).attr('height', H)
}

resize()
window.addEventListener('resize', () => { resize(); render() })

const edgeLayer = svg.append('g')
const nodeLayer = svg.append('g')

svg.on('click', function(e) {
  if (mode !== 'add') return
  const [x, y] = d3.pointer(e)
  addNode(x, y)
})

function setMode(m) {
  mode = m
  cf = null
  svg.style('cursor', m === 'add' ? 'crosshair' : m === 'connect' ? 'cell' : 'not-allowed')

  const mi = document.getElementById('modeIndicator')
  mi.textContent = { add: 'ADD NODE', connect: 'CONNECT MODE', delete: 'DELETE MODE' }[m]
  mi.className = 'mode-indicator ' + { add: 'm-add', connect: 'm-connect', delete: 'm-delete' }[m]
  render()
}

function setNodeType(t) {
  nodeType = t
  setMode('add')
}

function addNode(x, y) {
  const id = 'N' + (++nodeIdCounter)
  const prefix = { PC: 'PC', SERVER: 'SRV', ROUTER: 'RTR', FIREWALL: 'FW' }[nodeType]
  nodes.push({
    id,
    type: nodeType,
    label: `${prefix}-${nodeIdCounter}`,
    x, y,
    ip: randIP()
  })
  updateStats()
  render()
}

function randIP() {
  return `192.168.${rand(0, 5)}.${rand(1, 254)}`
}

function rand(a, b) {
  return Math.floor(Math.random() * (b - a + 1)) + a
}

function clearAll() {
  nodes = []
  edges = []
  cf = null
  selected = null
  criticalNode = null
  updateStats()
  render()
  showNodeInfo(null)
}

function updateStats() {
  document.getElementById('statNodes').textContent = nodes.length
  document.getElementById('statEdges').textContent = edges.length
}

function getNode(id) {
  return nodes.find(n => n.id === id) || { x: 0, y: 0 }
}

// render the canvas
function render() {
  // draw edges
  const links = edgeLayer.selectAll('.link').data(edges, d => d.id)

  links.enter().append('line').attr('class', 'link')
    .merge(links)
    .attr('x1', d => getNode(d.source).x)
    .attr('y1', d => getNode(d.source).y)
    .attr('x2', d => getNode(d.target).x)
    .attr('y2', d => getNode(d.target).y)
    .classed('suspicious', d => d.suspicious)

  links.exit().remove()

  // draw nodes
  const groups = nodeLayer.selectAll('.node-group').data(nodes, d => d.id)

  const newGroups = groups.enter().append('g')
    .attr('class', 'node-group')
    .attr('transform', d => `translate(${d.x},${d.y})`)
    .call(
      d3.drag()
        .on('start', onDragStart)
        .on('drag', onDrag)
        .on('end', () => {})
    )
    .on('click', (e, d) => {
      e.stopPropagation()
      if (mode === 'connect') connectNode(d)
      else if (mode === 'delete') removeNode(d)
      else { selected = d; showNodeInfo(d); render() }
    })

  newGroups.append('circle')
    .attr('class', 'node-ring')
    .attr('r', 22)
    .attr('fill', d => NODE_CFG[d.type].fill)
    .attr('stroke', d => NODE_CFG[d.type].stroke)

  newGroups.append('text').attr('class', 'node-icon').attr('y', 1)
    .text(d => NODE_CFG[d.type].icon)

  newGroups.append('text').attr('class', 'node-label').attr('y', 35)
  newGroups.append('text').attr('class', 'node-ip').attr('y', 45)
  newGroups.append('text').attr('class', 'critical-tag').attr('y', -28)

  const all = newGroups.merge(groups)

  all.attr('transform', d => `translate(${d.x},${d.y})`)
    .classed('selected', d => selected && d.id === selected.id)
    .classed('critical', d => d.id === criticalNode)

  all.select('.node-label').text(d => d.label)
  all.select('.node-ip').text(d => d.ip)
  all.select('.node-ring')
    .attr('fill', d => d.id === criticalNode ? '#fef9c3' : NODE_CFG[d.type].fill)
    .attr('stroke', d => d.id === criticalNode ? '#f59e0b' : NODE_CFG[d.type].stroke)
  all.select('.critical-tag')
    .text(d => d.id === criticalNode ? '⚠ HIGH RISK' : '')

  groups.exit().remove()

  // dashed ring for node being connected
  nodeLayer.selectAll('.node-group').select('.node-ring')
    .attr('stroke-dasharray', d => cf && cf.id === d.id ? '5,3' : null)
}

function flashNode(id) {
  const el = nodeLayer.selectAll('.node-group').filter(d => d.id === id)
  el.classed('active-hop', true)
  setTimeout(() => el.classed('active-hop', false), 500)
}

// drag handlers
function onDragStart(e, d) {
  if (mode !== 'add') return
  d3.select(this).raise()
}

function onDrag(e, d) {
  if (mode !== 'add') return
  d.x = Math.max(28, Math.min(W - 28, e.x))
  d.y = Math.max(28, Math.min(H - 28, e.y))
  render()
}

function connectNode(d) {
  if (!cf) { cf = d; render(); return }
  if (cf.id === d.id) { cf = null; render(); return }

  const exists = edges.some(e =>
    (e.source === cf.id && e.target === d.id) ||
    (e.source === d.id && e.target === cf.id)
  )

  if (!exists) {
    edges.push({
      id: `E${cf.id}-${d.id}`,
      source: cf.id,
      target: d.id,
      suspicious: false
    })
  }

  cf = null
  updateStats()
  render()
}

function removeNode(d) {
  nodes = nodes.filter(n => n.id !== d.id)
  edges = edges.filter(e => e.source !== d.id && e.target !== d.id)
  if (selected && selected.id === d.id) { selected = null; showNodeInfo(null) }
  updateStats()
  render()
}

// send packet - calls backend
async function sendPacket() {
  if (nodes.length < 2 || edges.length === 0) {
    addAlert('ERROR', 'need at least 2 connected nodes', 'low')
    return
  }

  const src = nodes[0]
  const tgt = nodes[nodes.length - 1]

  try {
    const res = await fetch('/api/simulate/packet', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ nodes, edges, sourceId: src.id, targetId: tgt.id })
    })

    const data = await res.json()

    if (data.blocked) {
      addAlert('BLOCKED', `packet from ${src.id} blocked by firewall`, 'high')
      return
    }

    if (!data.success) {
      addAlert('WARN', data.message, 'low')
      return
    }

    const pathNodes = data.path.map(id => nodes.find(n => n.id === id))
    animatePacket(pathNodes, false)

    packetCount++
    document.getElementById('statPackets').textContent = packetCount

    if (data.suspicious) {
      addAlert('ANOMALY', `suspicious: ${data.path.join(' → ')}`, 'high')
    } else {
      addAlert('INFO', `delivered: ${data.path.join(' → ')}`, 'low')
    }

  } catch(err) {
    console.error(err)
    addAlert('ERROR', 'server unreachable', 'high')
  }
}

async function simulateAttack() {
  if (nodes.length < 2 || edges.length === 0) {
    addAlert('ERROR', 'need at least 2 connected nodes', 'low')
    return
  }

  // pick random source and target
  const src = nodes[rand(0, nodes.length - 1)]
  const tgt = nodes[rand(0, nodes.length - 1)]
  if (src.id === tgt.id) { simulateAttack(); return }

  try {
    const res = await fetch('/api/simulate/packet', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ nodes, edges, sourceId: src.id, targetId: tgt.id })
    })

    const data = await res.json()
    if (data.blocked || !data.success) return

    const pathNodes = data.path.map(id => nodes.find(n => n.id === id))

    // mark edges along attack path as suspicious
    for (let i = 0; i < data.path.length - 1; i++) {
      const e = edges.find(e =>
        (e.source === data.path[i] && e.target === data.path[i + 1]) ||
        (e.source === data.path[i + 1] && e.target === data.path[i])
      )
      if (e) {
        e.suspicious = true
        setTimeout(() => { e.suspicious = false; render() }, 4000)
      }
    }

    render()
    animatePacket(pathNodes, true)

    packetCount++
    document.getElementById('statPackets').textContent = packetCount

  } catch(err) {
    console.error(err)
    addAlert('ERROR', 'server unreachable', 'high')
  }
}

function animatePacket(path, hostile) {
  if (!path || path.length < 2) return

  const dot = svg.append('circle')
    .attr('class', hostile ? 'packet hostile' : 'packet')
    .attr('cx', path[0].x)
    .attr('cy', path[0].y)
    .attr('r', 5)

  let step = 0

  function hop() {
    if (step >= path.length - 1) { dot.remove(); return }
    dot.transition().duration(480).ease(d3.easeLinear)
      .attr('cx', path[step + 1].x)
      .attr('cy', path[step + 1].y)
      .on('end', () => { step++; hop() })
  }

  hop()
}

function showNodeInfo(d) {
  const el = document.getElementById('nodeInfoBody')
  if (!d) { el.innerHTML = '<div class="np-empty">no node selected</div>'; return }

  const connCount = edges.filter(e => e.source === d.id || e.target === d.id).length

  el.innerHTML = `
    <div class="node-prop"><span class="np-key">ID</span><span class="np-val">${d.id}</span></div>
    <div class="node-prop"><span class="np-key">TYPE</span><span class="np-val">${d.type}</span></div>
    <div class="node-prop"><span class="np-key">LABEL</span><span class="np-val">${d.label}</span></div>
    <div class="node-prop"><span class="np-key">IP</span><span class="np-val">${d.ip}</span></div>
    <div class="node-prop"><span class="np-key">LINKS</span><span class="np-val">${connCount}</span></div>
    ${d.id === criticalNode ? '<div class="node-prop"><span class="np-key">RISK</span><span class="np-val critical-val">⚠ CRITICAL</span></div>' : ''}
  `
}

function addAlert(type, msg, severity) {
  const time = new Date().toLocaleTimeString()
  alertLog.unshift({ type, msg, severity, time })
  if (alertLog.length > 20) alertLog.pop()
  renderAlerts()
  document.getElementById('alertCountBadge').textContent = alertLog.length
}

function renderAlerts() {
  const el = document.getElementById('alertsList')
  if (!alertLog.length) { el.innerHTML = '<div class="alert-empty">no alerts</div>'; return }

  const typeClass = {
    INTRUSION: 't-intrusion',
    ANOMALY: 't-anomaly',
    BLOCKED: 't-blocked',
    INFO: 't-info',
    ERROR: 't-info',
    WARN: 't-info'
  }

  el.innerHTML = alertLog.map(a => `
    <div class="alert-card ${a.type === 'BLOCKED' ? 'sev-blocked' : a.severity === 'high' ? 'sev-high' : 'sev-low'}">
      <div class="alert-header">
        <span class="alert-type ${typeClass[a.type] || 't-info'}">${a.type}</span>
        <span class="alert-time">${a.time}</span>
      </div>
      <div class="alert-msg">${a.msg}</div>
    </div>
  `).join('')
}

// firewall stuff
async function fetchFirewallRules() {
  try {
    const res = await fetch('/api/firewall/rules')
    const data = await res.json()
    drawRulesTable(data.rules)
    document.getElementById('statRules').textContent = data.rules.length
  } catch(e) {
    console.error('could not fetch firewall rules', e)
  }
}

async function addFirewallRule() {
  const action = document.getElementById('fw-action').value
  const sourceIP = document.getElementById('fw-ip').value.trim()
  const port = parseInt(document.getElementById('fw-port').value) || 80
  const priority = parseInt(document.getElementById('fw-priority').value) || 1

  if (!sourceIP) {
    addAlert('ERROR', 'enter a source IP', 'low')
    return
  }

  try {
    await fetch('/api/firewall/rule', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action, sourceIP, port, priority })
    })
    document.getElementById('fw-ip').value = ''
    addAlert('INFO', `rule added: ${action} ${sourceIP}:${port}`, 'low')
  } catch(e) {
    addAlert('ERROR', 'server unreachable', 'high')
  }
}

async function deleteRule(id) {
  try {
    await fetch(`/api/firewall/rule/${id}`, { method: 'DELETE' })
    addAlert('INFO', `rule #${id} deleted`, 'low')
  } catch(e) {
    console.error(e)
  }
}

function drawRulesTable(rules) {
  const tbody = document.getElementById('fwTableBody')

  if (!rules || rules.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="fw-empty">no rules configured</td></tr>'
    return
  }

  tbody.innerHTML = rules.map(r => `
    <tr>
      <td>${r.id}</td>
      <td>${r.priority}</td>
      <td><span class="fw-badge ${r.action}">${r.action.toUpperCase()}</span></td>
      <td>${r.sourceIP}</td>
      <td>${r.port}</td>
      <td>${new Date(r.createdAt).toLocaleTimeString()}</td>
      <td><button class="fw-del" onclick="deleteRule(${r.id})">remove</button></td>
    </tr>
  `).join('')
}

// centrality analysis
async function runCentrality() {
  if (nodes.length < 2 || edges.length === 0) {
    addAlert('ERROR', 'need at least 2 connected nodes', 'low')
    return
  }

  try {
    const res = await fetch('/api/centrality', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ nodes, edges })
    })

    const data = await res.json()

    criticalNode = data.maxNode
    render()

    const maxObj = nodes.find(n => n.id === data.maxNode)

    document.getElementById('centCards').style.display = 'grid'
    document.getElementById('cmNode').textContent = maxObj ? maxObj.label : data.maxNode
    document.getElementById('cmNodeSub').textContent = maxObj ? maxObj.ip : '-'
    document.getElementById('cmScore').textContent = data.maxScore
    document.getElementById('cmTotal').textContent = nodes.length

    const chart = document.getElementById('centChart')
    chart.classList.add('visible')

    const sorted = Object.entries(data.centrality).sort((a, b) => b[1] - a[1])
    const max = sorted[0] ? sorted[0][1] : 1

    document.getElementById('centBars').innerHTML = sorted.map(([id, score]) => {
      const node = nodes.find(n => n.id === id)
      const label = node ? node.label : id
      const pct = max > 0 ? (score / max * 100) : 0
      const isMax = id === data.maxNode

      return `
        <div class="cent-row">
          <div class="cent-row-label">${label}</div>
          <div class="cent-bar-bg">
            <div class="cent-bar-fill ${isMax ? 'is-max' : ''}" style="width:0%" data-pct="${pct}"></div>
          </div>
          <div class="cent-row-score">${score}</div>
          ${isMax ? '<div class="cent-row-badge">HIGH RISK</div>' : ''}
        </div>
      `
    }).join('')

    // animate bars after render
    setTimeout(() => {
      document.querySelectorAll('.cent-bar-fill').forEach(el => {
        el.style.width = el.dataset.pct + '%'
      })
    }, 50)

    switchTab('centrality')
    addAlert('INFO', `analysis done - highest risk: ${maxObj ? maxObj.label : data.maxNode}`, 'low')

  } catch(e) {
    console.error(e)
    addAlert('ERROR', 'server unreachable', 'high')
  }
}

// load demo network on start
function loadDemo() {
  const cx = W / 2
  const cy = H / 2

  nodes = [
    { id: 'N1', type: 'FIREWALL', label: 'FW-1',  x: cx,       y: cy - 160, ip: '10.0.0.1' },
    { id: 'N2', type: 'ROUTER',   label: 'RTR-1', x: cx - 160, y: cy - 40,  ip: '192.168.0.1' },
    { id: 'N3', type: 'ROUTER',   label: 'RTR-2', x: cx + 160, y: cy - 40,  ip: '192.168.1.1' },
    { id: 'N4', type: 'SERVER',   label: 'SRV-1', x: cx,       y: cy + 80,  ip: '192.168.0.10' },
    { id: 'N5', type: 'PC',       label: 'PC-1',  x: cx - 260, y: cy + 80,  ip: '192.168.0.20' },
    { id: 'N6', type: 'PC',       label: 'PC-2',  x: cx + 260, y: cy + 80,  ip: '192.168.1.20' },
  ]

  nodeIdCounter = 6

  edges = [
    { id: 'E1', source: 'N1', target: 'N2', suspicious: false },
    { id: 'E2', source: 'N1', target: 'N3', suspicious: false },
    { id: 'E3', source: 'N2', target: 'N4', suspicious: false },
    { id: 'E4', source: 'N2', target: 'N5', suspicious: false },
    { id: 'E5', source: 'N3', target: 'N6', suspicious: false },
    { id: 'E6', source: 'N4', target: 'N3', suspicious: false },
  ]

  updateStats()
  render()
}

setTimeout(loadDemo, 100)
