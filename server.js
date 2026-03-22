const express    = require('express');
const http       = require('http');
const { Server } = require('socket.io');
const cors       = require('cors');
require('dotenv').config();

const app    = express();
const server = http.createServer(app);

// ── Socket.io ─────────────────────────────────────────
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
});

io.on('connection', (socket) => {
  console.log(`Client connected:    ${socket.id}`);
  socket.on('disconnect', () => {
    console.log(`Client disconnected: ${socket.id}`);
  });
});

// ── Middleware ────────────────────────────────────────
app.use(cors());
app.use(express.json());

// ── Health check ──────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({
    status:  'ok',
    message: 'NIDS server is running',
    sockets: io.engine.clientsCount,
  });
});

// ── Routes ────────────────────────────────────────────
const simulateRoutes = require('./simulate');
const topologyRoutes = require('./topology');
const alertRoutes    = require('./alerts');
const firewallRoutes = require('./firewall');
const analysisRoutes = require('./analysis');

app.use('/api/simulate', simulateRoutes(io));
app.use('/api/network',  topologyRoutes);
app.use('/api/alerts',   alertRoutes);
app.use('/api/firewall', firewallRoutes);
app.use('/api/analysis', analysisRoutes);

// ── Start ─────────────────────────────────────────────
const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`NIDS server running on http://localhost:${PORT}`);
  console.log(`Firewall rules: GET  http://localhost:${PORT}/api/firewall/rules`);
  console.log(`Graph analysis: POST http://localhost:${PORT}/api/analysis/graph`);
  console.log(`Compromise:     POST http://localhost:${PORT}/api/analysis/compromise`);
});
