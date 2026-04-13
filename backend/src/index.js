"use strict";
require("dotenv").config();
const express   = require("express");
const http      = require("http");
const cors      = require("cors");
const helmet    = require("helmet");
const morgan    = require("morgan");
const rateLimit = require("express-rate-limit");
const path      = require("path");
const fs        = require("fs");

// ── DB must init first so pragmas fire before any route uses it ───────────────
const db = require("./db/init");
const { setupWebSocket } = require("./services/ws");

// ── Global crash guards ───────────────────────────────────────────────────────
process.on("uncaughtException", (err) => {
  console.error("[CRASH] uncaughtException:", err.message, err.stack);
  // Don't exit — Railway will restart but we'd lose all WS connections
});
process.on("unhandledRejection", (reason) => {
  console.error("[CRASH] unhandledRejection:", reason);
});

const authRoutes     = require("./routes/auth");
const hospitalRoutes = require("./routes/hospitals");
const doctorRoutes   = require("./routes/doctors");
const bookingRoutes  = require("./routes/bookings");
const tokenRoutes    = require("./routes/tokens");
const patientRoutes  = require("./routes/patients");
const paymentRoutes  = require("./routes/payments");

const app  = express();
const PORT = process.env.PORT || 4000;

// ── Security headers ──────────────────────────────────────────────────────────
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  contentSecurityPolicy: false, // API server — no HTML to protect
}));

// ── CORS — wide open, security via JWT ───────────────────────────────────────
const corsOptions = {
  origin: true,
  credentials: true,
  methods: ["GET","POST","PATCH","PUT","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type","Authorization","X-Requested-With"],
  optionsSuccessStatus: 200,
};
app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

// ── Body parsing ──────────────────────────────────────────────────────────────
app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({ extended: true, limit: "20mb" }));

// ── Logging (skip health checks to reduce noise) ──────────────────────────────
app.use(morgan(process.env.NODE_ENV === "production" ? "combined" : "dev", {
  skip: (req) => req.path === "/api/health",
}));

// ── Rate limiting ─────────────────────────────────────────────────────────────
// Global: 1000 req / 15 min per IP (handles 300 users refreshing every 30s)
app.use("/api/", rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests — please slow down." },
  skip: (req) => req.method === "OPTIONS",
  keyGenerator: (req) => req.ip || "unknown",
}));

// Auth endpoints: stricter limit to prevent brute force
app.use("/api/auth/", rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { error: "Too many login attempts — try again in 15 minutes." },
  skip: (req) => req.method === "OPTIONS",
}));

// ── Response compression hint (Railway handles gzip at edge) ─────────────────
app.use((_req, res, next) => {
  res.setHeader("Vary", "Accept-Encoding");
  next();
});

// ── Static uploads ────────────────────────────────────────────────────────────
const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || "./uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
app.use("/uploads", express.static(UPLOAD_DIR, {
  maxAge: "7d",        // browsers cache photos for 7 days
  etag: true,
  lastModified: true,
}));

// ── API routes ────────────────────────────────────────────────────────────────
app.use("/api/auth",      authRoutes);
app.use("/api/hospitals", hospitalRoutes);
app.use("/api/doctors",   doctorRoutes);
app.use("/api/bookings",  bookingRoutes);
app.use("/api/tokens",    tokenRoutes);
app.use("/api/patients",  patientRoutes);
app.use("/api/payments",  paymentRoutes);

// ── Health check — also verifies DB is alive ──────────────────────────────────
app.get("/api/health", (_req, res) => {
  try {
    const counts = {
      users:     db.prepare("SELECT COUNT(*) as c FROM users").get().c,
      hospitals: db.prepare("SELECT COUNT(*) as c FROM hospitals").get().c,
      doctors:   db.prepare("SELECT COUNT(*) as c FROM doctors").get().c,
      bookings:  db.prepare("SELECT COUNT(*) as c FROM bookings").get().c,
    };
    res.json({ status: "ok", timestamp: new Date().toISOString(), counts });
  } catch (err) {
    res.status(500).json({ status: "error", error: err.message });
  }
});

// ── 404 ───────────────────────────────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ error: "Route not found" }));

// ── Global error handler ──────────────────────────────────────────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error("[ERROR]", err.message);
  if (!res.headersSent) {
    res.status(err.status || 500).json({
      error: err.message || "Internal server error",
    });
  }
});

// ── Start HTTP + WebSocket ────────────────────────────────────────────────────
const server = http.createServer(app);
setupWebSocket(server);

// Increase max connections and keep-alive for high load
server.maxConnections = 1000;
server.keepAliveTimeout = 65000;       // > Railway's 60s LB timeout
server.headersTimeout   = 66000;

server.listen(PORT, "0.0.0.0", () => {
  console.log(`\n🚀  Doctor Booked API  →  http://0.0.0.0:${PORT}`);
  console.log(`📡  WebSocket          →  ws://0.0.0.0:${PORT}/ws?session=ID`);
  console.log(`🩺  Health             →  http://0.0.0.0:${PORT}/api/health\n`);
});
