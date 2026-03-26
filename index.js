const express = require('express')
const cors = require('cors')
const path = require('path')
const http = require('http')
const { Server } = require('socket.io')
const { PrismaClient } = require('@prisma/client')
require('dotenv').config()

const app = express()
const httpServer = http.createServer(app)

// socket setup - took me a while to figure out the cors part here
const io = new Server(httpServer, {
  cors: { origin: '*' }
})

const prisma = new PrismaClient()

app.use(cors())
app.use(express.json())
app.use(express.static(path.join(__dirname)))

// socket connections
io.on('connection', (socket) => {
  console.log('connected:', socket.id)
  socket.emit('welcome', { message: 'Connected to NIDS server' })
  socket.on('disconnect', () => {
    console.log('disconnected:', socket.id)
  })
})

// BFS - finds path between two nodes in the graph
// ref: https://en.wikipedia.org/wiki/Breadth-first_search
function bfs(graph, start, end) {
  const visited = new Set()
  const queue = [[start, [start]]]

  while (queue.length > 0) {
    const [node, path] = queue.shift()

    if (node === end) return { found: true, path }
    if (visited.has(node)) continue

    visited.add(node)

    const neighbors = graph[node] || []
    for (const n of neighbors) {
      if (!visited.has(n)) {
        queue.push([n, [...path, n]])
      }
    }
  }

  return { found: false, path: [] }
}

// betweenness centrality
// basically counts how many shortest paths pass through each node
function calcCentrality(graph) {
  const nodes = Object.keys(graph)
  const scores = {}

  nodes.forEach(n => scores[n] = 0)

  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      const res = bfs(graph, nodes[i], nodes[j])
      if (!res.found) continue

      // skip first and last node, only count middle hops
      const middle = res.path.slice(1, -1)
      middle.forEach(n => scores[n]++)
    }
  }

  return scores
}

// helper to build adjacency list from nodes/edges arrays
function buildGraph(nodes, edges) {
  const graph = {}
  nodes.forEach(n => graph[n.id] = [])
  edges.forEach(e => {
    graph[e.source].push(e.target)
    graph[e.target].push(e.source)
  })
  return graph
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'NetworkCanvas.html'))
})

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' })
})

// firewall routes
app.get('/api/firewall/rules', async (req, res) => {
  try {
    const rules = await prisma.firewallRule.findMany({
      orderBy: { priority: 'asc' }
    })
    res.json({ rules })
  } catch(e) {
    console.error(e)
    res.status(500).json({ error: 'db error' })
  }
})

app.post('/api/firewall/rule', async (req, res) => {
  const { action, sourceIP, port, priority } = req.body

  const rule = await prisma.firewallRule.create({
    data: {
      action,
      sourceIP,
      port: parseInt(port),
      priority: parseInt(priority)
    }
  })

  const rules = await prisma.firewallRule.findMany({ orderBy: { priority: 'asc' } })
  io.emit('firewall:updated', { rules })
  res.json({ success: true, rule })
})

app.delete('/api/firewall/rule/:id', async (req, res) => {
  const id = parseInt(req.params.id)

  await prisma.firewallRule.delete({ where: { id } })

  const rules = await prisma.firewallRule.findMany({ orderBy: { priority: 'asc' } })
  io.emit('firewall:updated', { rules })
  res.json({ success: true })
})

// save network topology to db
app.post('/api/network/save', async (req, res) => {
  const { name, nodes, edges } = req.body
  const network = await prisma.network.create({
    data: {
      name: name || 'untitled',
      nodes: JSON.stringify(nodes),
      edges: JSON.stringify(edges)
    }
  })
  res.json({ success: true, network })
})

app.get('/api/network/:id', async (req, res) => {
  const id = parseInt(req.params.id)
  const network = await prisma.network.findUnique({ where: { id } })

  if (!network) return res.json({ success: false, message: 'not found' })

  res.json({
    success: true,
    network: {
      ...network,
      nodes: JSON.parse(network.nodes),
      edges: JSON.parse(network.edges)
    }
  })
})

app.get('/api/alerts', async (req, res) => {
  const alerts = await prisma.alert.findMany({
    orderBy: { createdAt: 'desc' },
    take: 50
  })
  res.json({ alerts })
})

// main packet simulation endpoint
app.post('/api/simulate/packet', async (req, res) => {
  const { nodes, edges, sourceId, targetId } = req.body

  const graph = buildGraph(nodes, edges)
  const result = bfs(graph, sourceId, targetId)

  if (!result.found) {
    return res.json({ success: false, message: 'no path between these nodes' })
  }

  const suspicious = result.path.length > 3

  // check against firewall rules
  const rules = await prisma.firewallRule.findMany({ orderBy: { priority: 'asc' } })
  const srcNode = nodes.find(n => n.id === sourceId)

  const blocked = rules.some(r => {
    if (r.action !== 'block') return false
    if (!srcNode) return false
    return srcNode.ip === r.sourceIP
  })

  if (blocked) {
    await prisma.alert.create({
      data: {
        type: 'BLOCKED',
        severity: 'high',
        message: `packet from ${sourceId} blocked by firewall`,
        path: result.path.join(' -> ')
      }
    })

    io.emit('alert:new', {
      type: 'BLOCKED',
      severity: 'high',
      path: result.path,
      message: `Packet from ${sourceId} BLOCKED by firewall rule`
    })

    return res.json({ success: false, blocked: true, message: 'blocked by firewall' })
  }

  // emit each hop with a delay so the animation looks smooth
  result.path.forEach((nodeId, i) => {
    setTimeout(() => {
      io.emit('packet:move', {
        nodeId,
        hopIndex: i,
        totalHops: result.path.length,
        suspicious
      })
    }, i * 600)
  })

  if (suspicious) {
    await prisma.alert.create({
      data: {
        type: 'ANOMALY',
        severity: 'high',
        message: `suspicious path: ${result.path.join(' -> ')}`,
        path: result.path.join(' -> ')
      }
    })

    setTimeout(() => {
      io.emit('alert:new', {
        type: 'ANOMALY',
        severity: 'high',
        path: result.path,
        message: `Suspicious path: ${result.path.join(' → ')}`
      })
    }, result.path.length * 600)
  }

  res.json({
    success: true,
    path: result.path,
    suspicious,
    message: suspicious ? 'anomalous path detected' : 'delivered'
  })
})

app.post('/api/centrality', (req, res) => {
  const { nodes, edges } = req.body
  const graph = buildGraph(nodes, edges)
  const scores = calcCentrality(graph)

  // find the node with highest score
  let maxNode = null
  let maxScore = -1

  Object.entries(scores).forEach(([id, score]) => {
    if (score > maxScore) {
      maxScore = score
      maxNode = id
    }
  })

  res.json({ centrality: scores, maxNode, maxScore })
})

const PORT = process.env.PORT || 3000
httpServer.listen(PORT, () => {
  console.log(`server running on http://localhost:${PORT}`)
})
