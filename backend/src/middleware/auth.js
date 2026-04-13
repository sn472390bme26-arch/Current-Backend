"use strict";
const jwt = require("jsonwebtoken");
const SECRET = process.env.JWT_SECRET || "fallback_dev_secret";

function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token  = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "No token provided" });
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
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
