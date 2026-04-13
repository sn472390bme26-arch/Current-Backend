"use strict";
const express = require("express");
const db      = require("../db/init");
const { requireAdmin } = require("../middleware/auth");

const router = express.Router();

router.get("/", requireAdmin, (req, res) => {
  try {
    const rows = db.prepare(
      "SELECT id, name, email, created_at FROM users WHERE role='patient' ORDER BY created_at DESC LIMIT 500"
    ).all();
    res.json(rows.map(r => ({ id: r.id, name: r.name, email: r.email || "", createdAt: r.created_at })));
  } catch (err) {
    console.error("[patients GET /]", err.message);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
