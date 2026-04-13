"use strict";
require("dotenv").config();
const express    = require("express");
const http       = require("http");
const cors       = require("cors");
const helmet     = require("helmet");
const morgan     = require("morgan");
const rateLimit  = require("express-rate-limit");
const compression = require("compression");
const path       = require("path");
const fs         = require("fs");

const db = require("./db/init");
const { setupWebSocket } = require("./services/ws");

// ── Global crash guards ───────────────────────────────────────────────────────
process.on("uncaughtException", (err) => {
  console.error("[CRASH] uncaughtException:", err.message, err.stack);
  // Log but don't exit — keeps WS connections alive
});
process.on("unhandledRejection", (reason) => {
  console.error("[CRASH] unhandledRejection:", reason);
});

// ── Graceful shutdown ─────────────────────────────────────────────────────────
process.on("SIGTERM", () => {
  console.log("[SHUTDOWN] SIGTERM received — closing server gracefully");
  server.close(() => {
    console.log("[SHUTDOWN] HTTP server closed");
    db.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10000); // force exit after 10s
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

// ── Trust Railway's proxy (fixes req.ip for rate limiting) ────────────────────
app.set("trust proxy", 1);

// ── Compression (reduces bandwidth by ~70%) ───────────────────────────────────
app.use(compression({
  level: 6,
  threshold: 1024, // only compress responses > 1KB
  filter: (req, res) => {
    if (req.headers["x-no-compression"]) return false;
    return compression.filter(req, res);
  },
}));

// ── Security headers ──────────────────────────────────────────────────────────
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  contentSecurityPolicy: false,
}));

// ── CORS ──────────────────────────────────────────────────────────────────────
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(",").map(o => o.trim())
  : true; // allow all in dev

const corsOptions = {
  origin: ALLOWED_ORIGINS,
  credentials: true,
  methods: ["GET","POST","PATCH","PUT","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type","Authorization","X-Requested-With"],
  optionsSuccessStatus: 200,
};
app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

// ── Body parsing ──────────────────────────────────────────────────────────────
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// ── Logging ───────────────────────────────────────────────────────────────────
app.use(morgan(process.env.NODE_ENV === "production" ? "combined" : "dev", {
  skip: (req) => req.path === "/api/health",
}));

// ── Rate limiting ─────────────────────────────────────────────────────────────
// Global: 500 req / 15 min per IP
app.use("/api/", rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests — please slow down." },
  skip: (req) => req.method === "OPTIONS",
  keyGenerator: (req) => req.ip || "unknown",
}));

// Auth: strict to prevent brute force
app.use("/api/auth/", rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: "Too many login attempts — try again in 15 minutes." },
  skip: (req) => req.method === "OPTIONS",
}));

// Payments: strict to prevent abuse
app.use("/api/payments/", rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { error: "Too many payment requests — please slow down." },
  skip: (req) => req.method === "OPTIONS",
}));

// ── Static uploads ────────────────────────────────────────────────────────────
const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || "./uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
app.use("/uploads", express.static(UPLOAD_DIR, {
  maxAge: "7d",
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

// ── Health check ──────────────────────────────────────────────────────────────
app.get("/api/health", (_req, res) => {
  try {
    const counts = {
      users:     db.prepare("SELECT COUNT(*) as c FROM users").get().c,
      hospitals: db.prepare("SELECT COUNT(*) as c FROM hospitals").get().c,
      doctors:   db.prepare("SELECT COUNT(*) as c FROM doctors").get().c,
      bookings:  db.prepare("SELECT COUNT(*) as c FROM bookings").get().c,
    };
    res.json({ status: "ok", timestamp: new Date().toISOString(), counts, uptime: process.uptime() });
  } catch (err) {
    res.status(500).json({ status: "error", error: err.message });
  }
});

// ── 404 ───────────────────────────────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ error: "Route not found" }));

// ── Global error handler ──────────────────────────────────────────────────────
app.use((err, _req, res, _next) => {
  console.error("[ERROR]", err.message);
  if (!res.headersSent) {
    res.status(err.status || 500).json({
      error: err.message || "Internal server error",
    });
  }
});

// ── HTTP + WebSocket server ───────────────────────────────────────────────────
const server = http.createServer(app);
setupWebSocket(server);

server.maxConnections  = 1000;
server.keepAliveTimeout = 65000;
server.headersTimeout   = 66000;

server.listen(PORT, "0.0.0.0", () => {
  console.log(`\n🚀  Doctor Booked API  →  http://0.0.0.0:${PORT}`);
  console.log(`📡  WebSocket          →  ws://0.0.0.0:${PORT}/ws?session=ID`);
  console.log(`🩺  Health             →  http://0.0.0.0:${PORT}/api/health\n`);
});

// Export for graceful shutdown reference
const serverRef = server;
module.exports = serverRef;
