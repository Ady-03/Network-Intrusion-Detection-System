# NIDS — Network Intrusion Detection System

A browser-based Network Intrusion Detection System that models a live computer network as a graph, detects suspicious traffic using graph algorithms, and shows real-time alerts on an interactive dashboard.

> **Campus Placement Portfolio Project** · Ayush · NIT Hamirpur · ECE

---

## Live Demo

> 🔗 _Coming soon after deployment_

---

## What It Does

- **Visual network canvas** — drag and drop PCs, Servers, Routers, and Firewalls onto a D3.js canvas and connect them with edges
- **BFS anomaly detection** — every packet travels the true shortest path (BFS); attack packets take evasive detours and are flagged when their hop count exceeds the BFS optimal
- **Real-time alerts** — Socket.io pushes intrusion alerts to every connected browser instantly, no refresh needed
- **Betweenness centrality** — calculates which node sits on the most shortest paths; that node's circle grows larger on the canvas to visually mark it as the highest attack target
- **Union-Find quarantine** — when a node is compromised, Union-Find clusters all reachable nodes and highlights them red for quarantine
- **Firewall rules engine** — block traffic between any two IPs; rules persist to MySQL and are respected during pathfinding
- **Save / load topology** — the full network state (nodes, edges, positions) saves to MySQL and can be restored in any session

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | HTML · D3.js · Socket.io client |
| Backend | Node.js · Express.js |
| Database | MySQL 8 · Prisma ORM |
| Real-time | Socket.io |
| Hosting | Vercel (frontend) · Render (backend) · Railway (MySQL) |

---

## Graph Algorithms

### BFS — Breadth First Search
Finds the true shortest path between any two nodes in O(V + E) time. Used as the "normal traffic baseline" — if a packet's actual hop count exceeds the BFS shortest by more than the threshold, it is flagged as an anomalous evasive route.

```
Normal packet:  FW-1 → RTR-1 → SRV-1        (2 hops, BFS optimal)
Attack packet:  FW-1 → RTR-2 → PC-1 → SRV-1  (3 hops, +1 — ANOMALY)
```

### Betweenness Centrality
For every pair of nodes (s, t), finds the BFS shortest path and credits every intermediate node it passes through. The node with the highest score is the most critical junction — the biggest attack target. Score is normalised 0.0 → 1.0 and visualised as node radius on the canvas.

### Union-Find (Disjoint Set Union)
Groups nodes into connectivity clusters using path-compressed union by rank. When a node is marked compromised, Union-Find immediately returns its entire connected cluster for quarantine. Near O(α(n)) — effectively constant time per operation.

### Evasive Path (Attack Simulation)
Finds the BFS shortest path first, then reruns BFS with the optimal intermediate nodes blocked. Forces the attacker through a longer detour, making anomaly detection meaningful.

---

## Project Structure

```
nids-project/
  server.js           — Express server + Socket.io
  pathfinding.js      — BFS, evasivePath, analysePacket
  graphAnalysis.js    — betweennessCentrality, unionFind, analyseGraph
  simulate.js         — POST /api/simulate/packet and /attack
  topology.js         — POST /api/network/save, GET /api/network/:id
  alerts.js           — GET /api/alerts, GET /api/alerts/stats
  firewall.js         — POST /api/firewall/rule, DELETE, GET
  analysis.js         — POST /api/analysis/graph, /compromise
  prisma/
    schema.prisma     — MySQL schema (Topology, Node, Edge, Alert, FirewallRule)
  NetworkCanvas_v4.html — complete frontend (single file)
```

---

## API Routes

| Method | Route | Description |
|---|---|---|
| POST | `/api/simulate/packet` | Run BFS, animate normal packet |
| POST | `/api/simulate/attack` | Run evasive path, detect anomaly |
| POST | `/api/network/save` | Save topology to MySQL |
| GET | `/api/network/:id` | Load topology from MySQL |
| GET | `/api/alerts` | Fetch last 50 alerts |
| GET | `/api/alerts/stats` | Alert counts by severity |
| POST | `/api/firewall/rule` | Add a block rule |
| DELETE | `/api/firewall/rule/:id` | Remove a rule |
| GET | `/api/firewall/rules` | List all active rules |
| POST | `/api/analysis/graph` | Betweenness centrality + Union-Find |
| POST | `/api/analysis/compromise` | Mark node compromised, get quarantine |

---

## Local Setup

### Prerequisites
- Node.js v18+
- MySQL 8 (local) or a Railway MySQL instance

### Steps

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/nids-project.git
cd nids-project

# 2. Install dependencies
npm install

# 3. Create .env file
echo 'DATABASE_URL="mysql://root:YOUR_PASSWORD@localhost:3306/nids_db"' > .env

# 4. Create the database
mysql -u root -p -e "CREATE DATABASE nids_db;"

# 5. Run Prisma migrations
npx prisma migrate dev

# 6. Start the server
node server.js

# 7. Open the frontend
# Open NetworkCanvas_v4.html in your browser
```

The server runs on `http://localhost:3001`. Open `NetworkCanvas_v4.html` directly in your browser — no build step needed.

### Running Tests

```bash
node pathfinding.test.js      # 35 tests — BFS, evasivePath, anomaly detection
node graphAnalysis.test.js    # 30 tests — centrality, Union-Find, quarantine
```

---

## Weekly Build Log

| Week | Goal | Status |
|---|---|---|
| Week 1 | D3.js network canvas with drag-drop nodes | ✅ Done |
| Week 2 | BFS anomaly detection + Express + MySQL | ✅ Done |
| Week 3 | Socket.io real-time alerts + frontend wired to backend | ✅ Done |
| Week 4 | Betweenness centrality + Union-Find + Firewall rules engine | ✅ Done |
| Week 5 | Deploy + README + interview prep | 🔄 In progress |

---

## Interview Pitch (60 seconds)

> "I built a browser-based Network Intrusion Detection System that models a live network as a graph. It uses BFS for anomaly detection by comparing a packet's actual hop count to the shortest known path — any deviation above the threshold triggers an alert. Betweenness centrality identifies the highest-risk node by counting how many shortest paths pass through it, visualised as node size on the canvas. Union-Find clusters compromised devices for quarantine in near-constant time. A firewall rules engine blocks specific IP pairs during pathfinding. Real-time alerts are pushed to all connected browsers via Socket.io, and the full topology persists to MySQL through a Node.js/Prisma backend. The whole thing is deployed on Vercel, Render, and Railway."

---

## Screenshots

_Add screenshots here after deployment_

---

## License

MIT
