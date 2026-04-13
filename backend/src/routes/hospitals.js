"use strict";
const express = require("express");
const db      = require("../db/init");
const { requireAdmin } = require("../middleware/auth");
const multer  = require("multer");
const path    = require("path");
const fs      = require("fs");

const router = express.Router();

// ── Multer: store in memory (we'll base64-encode and save in DB) ──────────────
// This means photos survive Railway redeploys — no filesystem dependency
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: (Number(process.env.MAX_FILE_SIZE_MB) || 5) * 1024 * 1024 },
  fileFilter: (_req, file, cb) =>
    file.mimetype.startsWith("image/") ? cb(null, true) : cb(new Error("Images only")),
});

// ── Ensure photo_data column exists (safe migration) ─────────────────────────
try {
  db.prepare("ALTER TABLE hospitals ADD COLUMN photo_data TEXT").run();
  console.log("[hospitals] Added photo_data column for persistent photo storage");
} catch (_) {
  // Column already exists — fine
}

function row2hospital(r, req) {
  if (!r) return null;
  const doctorCount = db.prepare("SELECT COUNT(*) as c FROM doctors WHERE hospital_id=?").get(r.id).c;

  // Photo priority: base64 in DB (permanent) > URL from filesystem (may disappear)
  let photoUrl = null;
  if (r.photo_data) {
    // Base64 stored directly in DB — always available, survives redeploys
    photoUrl = r.photo_data;
  } else if (r.photo_url) {
    // Legacy: relative path — build full URL
    if (r.photo_url.startsWith("http")) {
      photoUrl = r.photo_url;
    } else {
      const proto = req.headers["x-forwarded-proto"] || req.protocol || "https";
      const host  = req.headers["x-forwarded-host"] || req.headers.host || "";
      photoUrl = `${proto}://${host}${r.photo_url}`;
    }
  }

  return {
    id: r.id, name: r.name, area: r.area,
    address: r.address || "", phone: r.phone || "",
    rating: r.rating, gradient: r.gradient,
    photoUrl,
    doctorCount,
  };
}

// ── GET all hospitals ─────────────────────────────────────────────────────────
router.get("/", (req, res) => {
  try {
    const rows = db.prepare("SELECT * FROM hospitals ORDER BY name ASC").all();
    res.json(rows.map(r => row2hospital(r, req)));
  } catch (err) {
    console.error("[hospitals GET /]", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── GET single hospital ───────────────────────────────────────────────────────
router.get("/:id", (req, res) => {
  try {
    const row = db.prepare("SELECT * FROM hospitals WHERE id=?").get(req.params.id);
    if (!row) return res.status(404).json({ error: "Hospital not found" });
    res.json(row2hospital(row, req));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST create hospital ──────────────────────────────────────────────────────
router.post("/", requireAdmin, (req, res) => {
  try {
    const { name, area, address = "", phone = "", gradient = "from-slate-400 to-slate-600" } = req.body;
    if (!name || !area) return res.status(400).json({ error: "name and area are required" });

    const id = `h_${Date.now()}`;
    db.prepare(
      "INSERT INTO hospitals (id, name, area, address, phone, gradient) VALUES (?,?,?,?,?,?)"
    ).run(id, name, area, address, phone, gradient);

    res.status(201).json(row2hospital(db.prepare("SELECT * FROM hospitals WHERE id=?").get(id), req));
  } catch (err) {
    console.error("[hospitals POST]", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── PATCH update hospital ─────────────────────────────────────────────────────
router.patch("/:id", requireAdmin, (req, res) => {
  try {
    const row = db.prepare("SELECT * FROM hospitals WHERE id=?").get(req.params.id);
    if (!row) return res.status(404).json({ error: "Hospital not found" });

    const { name, area, address, phone } = req.body;
    db.prepare(
      "UPDATE hospitals SET name=COALESCE(?,name), area=COALESCE(?,area), address=COALESCE(?,address), phone=COALESCE(?,phone) WHERE id=?"
    ).run(name || null, area || null, address ?? null, phone ?? null, req.params.id);

    res.json(row2hospital(db.prepare("SELECT * FROM hospitals WHERE id=?").get(req.params.id), req));
  } catch (err) {
    console.error("[hospitals PATCH]", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── POST upload hospital photo ────────────────────────────────────────────────
// Stores photo as base64 directly in the database — survives all redeploys
router.post("/:id/photo", requireAdmin, upload.single("photo"), (req, res) => {
  try {
    const row = db.prepare("SELECT * FROM hospitals WHERE id=?").get(req.params.id);
    if (!row) return res.status(404).json({ error: "Hospital not found" });
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });

    // Convert uploaded file buffer to base64 data URL
    const base64 = `data:${req.file.mimetype};base64,${req.file.buffer.toString("base64")}`;

    // Save to DB — clears legacy photo_url so base64 takes priority
    db.prepare("UPDATE hospitals SET photo_data=?, photo_url=NULL WHERE id=?").run(base64, req.params.id);

    console.log(`[hospitals photo] saved base64 for id=${req.params.id} size=${req.file.size} bytes`);
    res.json({ photoUrl: base64 });
  } catch (err) {
    console.error("[hospitals photo]", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── POST accept base64 photo directly (from frontend FileReader) ──────────────
router.post("/:id/photo-base64", requireAdmin, (req, res) => {
  try {
    const row = db.prepare("SELECT * FROM hospitals WHERE id=?").get(req.params.id);
    if (!row) return res.status(404).json({ error: "Hospital not found" });

    const { base64 } = req.body;
    if (!base64 || !base64.startsWith("data:image/"))
      return res.status(400).json({ error: "Invalid base64 image data" });

    db.prepare("UPDATE hospitals SET photo_data=?, photo_url=NULL WHERE id=?").run(base64, req.params.id);
    console.log(`[hospitals photo-base64] saved for id=${req.params.id}`);
    res.json({ photoUrl: base64 });
  } catch (err) {
    console.error("[hospitals photo-base64]", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── DELETE hospital ───────────────────────────────────────────────────────────
router.delete("/:id", requireAdmin, (req, res) => {
  try {
    const count = db.prepare("SELECT COUNT(*) as c FROM doctors WHERE hospital_id=?").get(req.params.id).c;
    if (count > 0)
      return res.status(409).json({ error: "Cannot delete hospital with assigned doctors. Remove doctors first." });

    db.prepare("DELETE FROM hospitals WHERE id=?").run(req.params.id);
    res.json({ success: true });
  } catch (err) {
    console.error("[hospitals DELETE]", err.message);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
