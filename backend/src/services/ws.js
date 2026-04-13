"use strict";
const { WebSocketServer } = require("ws");

// sessionId → Set<WebSocket>
const rooms = new Map();

// Heartbeat: ping every client every 30s, drop dead ones
// Without this, dead connections pile up and eat memory
const PING_INTERVAL = 30_000;

function setupWebSocket(server) {
  const wss = new WebSocketServer({ server, path: "/ws" });

  // Periodic heartbeat to clean up dead connections
  const heartbeat = setInterval(() => {
    wss.clients.forEach((ws) => {
      if (ws.isAlive === false) {
        ws.terminate();
        return;
      }
      ws.isAlive = false;
      ws.ping();
    });
  }, PING_INTERVAL);

  wss.on("close", () => clearInterval(heartbeat));

  wss.on("connection", (ws, req) => {
    ws.isAlive = true;
    ws.on("pong", () => { ws.isAlive = true; });

    const url    = new URL(req.url, "http://localhost");
    const sessionId = url.searchParams.get("session");
    if (!sessionId) { ws.close(1008, "session param required"); return; }

    if (!rooms.has(sessionId)) rooms.set(sessionId, new Set());
    const room = rooms.get(sessionId);
    room.add(ws);

    // Send current connection count to client
    try {
      ws.send(JSON.stringify({ type: "connected", sessionId, viewers: room.size }));
    } catch {}

    ws.on("close", () => {
      room.delete(ws);
      if (room.size === 0) rooms.delete(sessionId);
    });

    ws.on("error", (err) => {
      console.error(`[WS] error session=${sessionId}:`, err.message);
      ws.terminate();
    });
  });

  console.log("✅  WebSocket server ready at /ws?session=SESSION_ID");
  return wss;
}

/** Broadcast JSON to all live clients in a session room */
function broadcast(sessionId, payload) {
  const room = rooms.get(sessionId);
  if (!room || room.size === 0) return;
  const msg = JSON.stringify(payload);
  for (const client of room) {
    if (client.readyState === 1 /* OPEN */) {
      try { client.send(msg); } catch (e) {
        console.error("[WS] send failed:", e.message);
      }
    }
  }
}

/** Return number of live viewers for a session */
function viewers(sessionId) {
  return rooms.get(sessionId)?.size ?? 0;
}

module.exports = { setupWebSocket, broadcast, viewers };
