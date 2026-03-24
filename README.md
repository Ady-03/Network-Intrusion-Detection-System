NIDS — Network Intrusion Detection System

A browser-based Network Intrusion Detection System that models a live computer network as a graph, detects suspicious traffic using graph algorithms, and shows real-time alerts on an interactive dashboard.

Live Demo Link:
> 🔗 _Coming soon after deployment_

What It Does:

- **Visual network canvas** — drag and drop PCs, Servers, Routers, and Firewalls onto a D3.js canvas and connect them with edges
- **BFS anomaly detection** — every packet travels the true shortest path (BFS); attack packets take evasive detours and are flagged when their hop count exceeds the BFS optimal
- **Real-time alerts** — Socket.io pushes intrusion alerts to every connected browser instantly, no refresh needed
- **Betweenness centrality** — calculates which node sits on the most shortest paths; that node's circle grows larger on the canvas to visually mark it as the highest attack target
- **Union-Find quarantine** — when a node is compromised, Union-Find clusters all reachable nodes and highlights them red for quarantine
- **Firewall rules engine** — block traffic between any two IPs; rules persist to MySQL and are respected during pathfinding
- **Save / load topology** — the full network state (nodes, edges, positions) saves to MySQL and can be restored in any session

Tech Stack:
1) Frontend -> HTML, D3.js, Socket.io
2) Backend ->Node.js, Express.js
3) Database -> MySQL, Prisma ORM
4) Real-time -> Socket.io
5) Deployment -> Vercel (frontend), Render (backend), Railway (MySQL)


Graph Algorithms:

1) BFS — Breadth First Search

it finds the true shortest path between any two nodes in O(V + E) time. 
Used as the "normal traffic baseline" i.e, if a packet's actual hop count exceeds the BFS shortest by more than the threshold, it is flagged as an anomalous evasive route.

example:-
    Normal packet:  FW-1 → RTR-1 → SRV-1        (2 hops, BFS optimal)
    Attack packet:  FW-1 → RTR-2 → PC-1 → SRV-1  (3 hops, +1 — ANOMALY)

2) Betweenness Centrality
    For every pair of nodes (s, t), finds the BFS shortest path and credits every intermediate node it passes through. The node with the      highest score is the most critical junction — the biggest attack target. Score is normalised 0.0 → 1.0 and visualised as node radius      on   the canvas.

3) Union-Find (Disjoint Set Union)
    Groups nodes into connectivity clusters using path-compressed union by rank. When a node is marked compromised, Union-Find                immediately returns its entire connected cluster for quarantine. Near O(α(n)) — effectively constant time per operation.

4) Evasive Path (Attack Simulation)
    Finds the BFS shortest path first, then reruns BFS with the optimal intermediate nodes blocked. Forces the attacker through a longer      detour, making anomaly detection meaningful.


The server runs on `http://localhost:3001`. Open `NetworkCanvas_v4.html` directly in your browser — no build step needed.
## Screenshots

_Add screenshots here after deployment_
