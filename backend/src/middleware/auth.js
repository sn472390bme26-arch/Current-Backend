"use strict";
const jwt = require("jsonwebtoken");

const SECRET = process.env.JWT_SECRET;
if (!SECRET || SECRET === "fallback_dev_secret") {
  if (process.env.NODE_ENV === "production") {
    console.error("[FATAL] JWT_SECRET is not set! Set it in Railway environment variables.");
    process.exit(1);
  } else {
    console.warn("[AUTH] WARNING: Using fallback JWT secret. Set JWT_SECRET in .env");
  }
}

const JWT_SECRET = SECRET || "fallback_dev_secret";

function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token  = header.startsWith("Bearer ") ? header.slice(7).trim() : null;
  if (!token) return res.status(401).json({ error: "No token provided" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    if (err.name === "TokenExpiredError")
      return res.status(401).json({ error: "Session expired. Please log in again." });
    return res.status(401).json({ error: "Invalid token. Please log in again." });
  }
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== "admin")
      return res.status(403).json({ error: "Admin access required" });
    next();
  });
}

function requireDoctor(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== "doctor")
      return res.status(403).json({ error: "Doctor access required" });
    next();
  });
}

function requireDoctorOrAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== "doctor" && req.user.role !== "admin")
      return res.status(403).json({ error: "Doctor or admin access required" });
    next();
  });
}

module.exports = { requireAuth, requireAdmin, requireDoctor, requireDoctorOrAdmin };
