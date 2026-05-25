"use strict";
const express = require("express");
const db      = require("../db/init");
const { requireAdmin, requireDoctorOrAdmin } = require("../middleware/auth");

const router = express.Router();

function cleanCode(value) {
  return String(value || "").trim().toUpperCase().replace(/\s+/g, "");
}

function shortLabel(value, length) {
  return String(value || "")
    .trim()
    .slice(0, length)
    .replace(/\s+/g, "")
    .toUpperCase();
}

function doctorInitials(name) {
  return String(name || "")
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .map(part => part[0])
    .join("")
    .toUpperCase();
}

function parseSerial(code) {
  const match = String(code || "").match(/(\d+)$/);
  return match ? parseInt(match[1], 10) || 0 : 0;
}

function hospitalCodeParts(hospital) {
  const hospitalShort = shortLabel(hospital.name, 4);
  const cityShort = shortLabel(hospital.area, 3);
  return { hospitalShort, cityShort };
}

function nextDoctorCode({ name, hospitalId }) {
  const hospital = db.prepare("SELECT name, area FROM hospitals WHERE id=?").get(hospitalId);
  if (!hospital) throw new Error("Hospital not found");

  const { hospitalShort, cityShort } = hospitalCodeParts(hospital);
  const initials = doctorInitials(name);
  const prefix = `${initials}.${hospitalShort}.${cityShort}`;

  const rows = db.prepare("SELECT code FROM doctors WHERE hospital_id=?").all(hospitalId);
  let maxSerial = 0;

  for (const row of rows) {
    const code = cleanCode(row.code);
    if (!code.startsWith(`${prefix}.`)) continue;
    maxSerial = Math.max(maxSerial, parseSerial(code));
  }

  let serial = maxSerial + 1;
  while (true) {
    const candidate = `${prefix}.${String(serial).padStart(2, "0")}`;
    const existing = db.prepare("SELECT 1 FROM doctors WHERE UPPER(code)=UPPER(?) LIMIT 1").get(candidate);
    if (!existing) return candidate;
    serial += 1;
  }
}

function row2doctor(r) {
  if (!r) return null;
  return {
    id: r.id, hospitalId: r.hospital_id, code: r.code,
    name: r.name, specialty: r.specialty,
    phone: r.phone || "", contactPhone: r.phone || "",
    bio: r.bio || "", photo: r.photo || null,
    price: r.price, consultationFee: r.consultation_fee,
    tokensPerSession: r.tokens_per_session,
    sessions: r.sessions ? r.sessions.split(",") : ["morning","afternoon"],
    sessionTimings: r.session_timings ? JSON.parse(r.session_timings) : null,
    isAvailable: r.is_available === 1,
    yearsOfExperience: r.years_of_experience || "",
    education: r.education || "",
    languages: r.languages ? JSON.parse(r.languages) : [],
  };
}

// ── GET all doctors ───────────────────────────────────────────────────────────
router.get("/", (req, res) => {
  try {
    const rows = req.query.hospitalId
      ? db.prepare("SELECT * FROM doctors WHERE hospital_id=? ORDER BY name ASC").all(req.query.hospitalId)
      : db.prepare("SELECT * FROM doctors ORDER BY name ASC").all();
    res.json(rows.map(row2doctor));
  } catch (err) {
    console.error("[doctors GET /]", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── GET single doctor ─────────────────────────────────────────────────────────
router.get("/:id", (req, res) => {
  try {
    const row = db.prepare("SELECT * FROM doctors WHERE id=?").get(req.params.id);
    if (!row) return res.status(404).json({ error: "Doctor not found" });
    res.json(row2doctor(row));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST create doctor ────────────────────────────────────────────────────────
router.post("/", requireAdmin, (req, res) => {
  try {
    const { name, specialty, hospitalId, phone = "", bio = "",
            price = 10, tokensPerSession = 20,
            sessions = ["morning","afternoon"],
            sessionTimings = null, yearsOfExperience = "",
            education = "", languages = [] } = req.body;

    if (!name || !specialty || !hospitalId)
      return res.status(400).json({ error: "name, specialty, and hospitalId are required" });

    const hospital = db.prepare("SELECT id FROM hospitals WHERE id=?").get(hospitalId);
    if (!hospital) return res.status(404).json({ error: "Hospital not found" });

    const code = nextDoctorCode({ name, hospitalId });
    const id   = `d_${Date.now()}`;

    db.prepare(`
      INSERT INTO doctors
        (id, hospital_id, code, name, specialty, phone, bio, price, consultation_fee,
         tokens_per_session, sessions, session_timings, is_available,
         years_of_experience, education, languages)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,?)
    `).run(
      id, hospitalId, code, name, specialty, phone, bio, price, price,
      tokensPerSession,
      Array.isArray(sessions) ? sessions.join(",") : sessions,
      sessionTimings ? JSON.stringify(sessionTimings) : null,
      yearsOfExperience, education,
      languages.length ? JSON.stringify(languages) : null
    );

    res.status(201).json(row2doctor(db.prepare("SELECT * FROM doctors WHERE id=?").get(id)));
  } catch (err) {
    console.error("[doctors POST]", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── PATCH update doctor ───────────────────────────────────────────────────────
router.patch("/:id", requireDoctorOrAdmin, (req, res) => {
  try {
    const row = db.prepare("SELECT * FROM doctors WHERE id=?").get(req.params.id);
    if (!row) return res.status(404).json({ error: "Doctor not found" });

    if (req.user.role === "doctor" && req.user.doctorId !== req.params.id)
      return res.status(403).json({ error: "Cannot edit another doctor's profile" });

    const {
      specialty, hospitalId, isAvailable, bio, sessionTimings,
      yearsOfExperience, education, languages, tokensPerSession,
      phone, contactPhone, photo, name, sessions, price, consultationFee, code,
    } = req.body;

    if (code !== undefined && req.user.role !== "admin") {
      return res.status(403).json({ error: "Only admins can change doctor codes" });
    }

    // Never overwrite phone with empty string — phone is the login password
    const finalPhone = (contactPhone || phone || "").trim() || null;
    const finalCode = code === undefined ? null : cleanCode(code);

    if (code !== undefined && !finalCode) {
      return res.status(400).json({ error: "code cannot be empty" });
    }

    if (finalCode) {
      const existing = db.prepare("SELECT id FROM doctors WHERE UPPER(code)=UPPER(?) AND id<>?").get(finalCode, req.params.id);
      if (existing) return res.status(409).json({ error: "Doctor code already exists" });
    }

    db.prepare(`
      UPDATE doctors SET
        name                = COALESCE(?, name),
        specialty           = COALESCE(?, specialty),
        hospital_id         = COALESCE(?, hospital_id),
        is_available        = COALESCE(?, is_available),
        bio                 = COALESCE(?, bio),
        photo               = COALESCE(?, photo),
        session_timings     = COALESCE(?, session_timings),
        sessions            = COALESCE(?, sessions),
        years_of_experience = COALESCE(?, years_of_experience),
        education           = COALESCE(?, education),
        languages           = COALESCE(?, languages),
        tokens_per_session  = COALESCE(?, tokens_per_session),
        price               = COALESCE(?, price),
        consultation_fee    = COALESCE(?, consultation_fee),
        phone               = COALESCE(?, phone),
        code                = COALESCE(?, code)
      WHERE id=?
    `).run(
      name         || null,
      specialty    || null,
      hospitalId   || null,
      isAvailable !== undefined ? (isAvailable ? 1 : 0) : null,
      bio          ?? null,
      photo        ?? null,
      sessionTimings ? JSON.stringify(sessionTimings) : null,
      sessions ? (Array.isArray(sessions) ? sessions.join(",") : sessions) : null,
      yearsOfExperience ?? null,
      education    ?? null,
      languages    ? JSON.stringify(languages) : null,
      tokensPerSession ?? null,
      price        ?? null,
      consultationFee ?? price ?? null,
      finalPhone,
      finalCode,
      req.params.id
    );

    res.json(row2doctor(db.prepare("SELECT * FROM doctors WHERE id=?").get(req.params.id)));
  } catch (err) {
    console.error("[doctors PATCH]", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── DELETE doctor ─────────────────────────────────────────────────────────────
router.delete("/:id", requireAdmin, (req, res) => {
  try {
    const row = db.prepare("SELECT * FROM doctors WHERE id=?").get(req.params.id);
    if (!row) return res.status(404).json({ error: "Doctor not found" });

    db.transaction(() => {
      db.prepare("UPDATE bookings SET status='cancelled' WHERE doctor_id=? AND status='confirmed'").run(req.params.id);
      db.prepare("DELETE FROM token_states WHERE doctor_id=?").run(req.params.id);
      db.prepare("DELETE FROM doctors WHERE id=?").run(req.params.id);
    })();

    console.log(`[doctors DELETE] id=${req.params.id}`);
    res.json({ success: true });
  } catch (err) {
    console.error("[doctors DELETE]", err.message);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
