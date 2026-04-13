"use strict";
const { WebSocketServer } = require("ws");

// sessionId → Set<WebSocket>
const rooms = new Map();

const PING_INTERVAL    = 30_000;  // 30s heartbeat
const MAX_WS_PER_SESSION = 200;   // prevent memory bombs
const MAX_TOTAL_WS       = 1000;  // hard cap for 1000 users

function setupWebSocket(server) {
  const wss = new WebSocketServer({
    server,
    path: "/ws",
    maxPayload: 16 * 1024, // 16KB max message size — clients only send pongs
    clientTracking: true,
  });

  // ── Heartbeat — drop dead connections every 30s ───────────────────────────
  const heartbeat = setInterval(() => {
    let alive = 0, dropped = 0;
    wss.clients.forEach((ws) => {
      if (ws.isAlive === false) {
        ws.terminate();
        dropped++;
        return;
      }
      ws.isAlive = false;
      try { ws.ping(); } catch (_) {}
      alive++;
    });
    if (dropped > 0) console.log(`[WS] Heartbeat: ${alive} alive, ${dropped} dropped`);
  }, PING_INTERVAL);

  wss.on("close", () => clearInterval(heartbeat));

  wss.on("connection", (ws, req) => {
    // ── Hard cap — reject if server is at max capacity ────────────────────
    if (wss.clients.size > MAX_TOTAL_WS) {
      ws.close(1013, "Server at capacity — try again shortly");
      return;
    }

    ws.isAlive = true;
    ws.on("pong", () => { ws.isAlive = true; });

    // ── Parse session ID ──────────────────────────────────────────────────
    let sessionId;
    try {
      const url = new URL(req.url, "http://localhost");
      sessionId = url.searchParams.get("session");
    } catch (_) {}

    if (!sessionId) { ws.close(1008, "session param required"); return; }
    if (sessionId.length > 200) { ws.close(1008, "invalid session"); return; }

    // ── Per-session cap ───────────────────────────────────────────────────
    if (!rooms.has(sessionId)) rooms.set(sessionId, new Set());
    const room = rooms.get(sessionId);

    if (room.size >= MAX_WS_PER_SESSION) {
      ws.close(1013, "Session at capacity");
      return;
    }

    room.add(ws);
    ws._sessionId = sessionId;

    try {
      ws.send(JSON.stringify({ type: "connected", sessionId, viewers: room.size }));
    } catch (_) {}

    ws.on("close", () => {
      room.delete(ws);
      if (room.size === 0) rooms.delete(sessionId);
    });

    ws.on("error", (err) => {
      console.error(`[WS] error session=${sessionId}:`, err.message);
      try { ws.terminate(); } catch (_) {}
    });

    // Ignore any messages from clients — this is a read-only socket
    ws.on("message", () => {});
  });

  // ── Stats log every 5 minutes ─────────────────────────────────────────────
  setInterval(() => {
    const totalClients = wss.clients.size;
    const totalRooms   = rooms.size;
    if (totalClients > 0) {
      console.log(`[WS] Stats: ${totalClients} connections across ${totalRooms} sessions`);
    }
  }, 5 * 60 * 1000);

  console.log("✅  WebSocket server ready at /ws?session=SESSION_ID");
  return wss;
}

/** Broadcast JSON to all live clients in a session room */
function broadcast(sessionId, payload) {
  const room = rooms.get(sessionId);
  if (!room || room.size === 0) return;
  const msg = JSON.stringify(payload);
  const dead = [];
  for (const client of room) {
    if (client.readyState === 1 /* OPEN */) {
      try { client.send(msg); } catch (e) {
        console.error("[WS] send failed:", e.message);
        dead.push(client);
      }
    } else {
      dead.push(client);
    }
  }
  // Clean up dead clients found during broadcast
  for (const c of dead) {
    room.delete(c);
    try { c.terminate(); } catch (_) {}
  }
  if (room.size === 0) rooms.delete(sessionId);
}

/** Return number of live viewers for a session */
function viewers(sessionId) {
  return rooms.get(sessionId)?.size ?? 0;
}

module.exports = { setupWebSocket, broadcast, viewers };
