"use strict";
const express = require("express");
const db      = require("../db/init");
const { requireAuth, requireAdmin, requireDoctorOrAdmin } = require("../middleware/auth");
const { broadcast } = require("../services/ws");

const router = express.Router();

function row2booking(r) {
  if (!r) return null;
  return {
    id: r.id, patientId: r.patient_id, patientName: r.patient_name,
    doctorId: r.doctor_id, doctorName: r.doctor_name, hospitalName: r.hospital_name,
    date: r.date, session: r.session, tokenNumber: r.token_number,
    sessionId: r.session_id, paymentDone: r.payment_done === 1, status: r.status,
    phone: r.phone || "", complaint: r.complaint || "", createdAt: r.created_at,
  };
}

// ── GET bookings ──────────────────────────────────────────────────────────────
router.get("/", requireAuth, (req, res) => {
  try {
    let rows;
    if (req.user.role === "admin") {
      rows = db.prepare("SELECT * FROM bookings ORDER BY created_at DESC LIMIT 500").all();
    } else if (req.user.role === "doctor") {
      rows = db.prepare(
        "SELECT * FROM bookings WHERE doctor_id=? ORDER BY date DESC, session ASC, token_number ASC LIMIT 300"
      ).all(req.user.doctorId);
    } else {
      rows = db.prepare(
        "SELECT * FROM bookings WHERE patient_id=? ORDER BY created_at DESC"
      ).all(req.user.id);
    }
    res.json(rows.map(row2booking));
  } catch (err) {
    console.error("[bookings GET /]", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── GET bookings for a session ────────────────────────────────────────────────
router.get("/session/:sessionId", requireAuth, (req, res) => {
  try {
    const rows = db.stmts.getBookingsForSession.all(req.params.sessionId);
    res.json(rows.map(row2booking));
  } catch (err) {
    console.error("[bookings GET /session]", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── POST create booking ───────────────────────────────────────────────────────
router.post("/", requireAuth, (req, res) => {
  if (req.user.role !== "patient")
    return res.status(403).json({ error: "Only patients can create bookings" });

  const { doctorId, date, session, complaint = "", phone = "" } = req.body;
  if (!doctorId || !date || !session)
    return res.status(400).json({ error: "doctorId, date, and session are required" });

  try {
    const doctor   = db.prepare("SELECT * FROM doctors WHERE id=?").get(doctorId);
    if (!doctor)   return res.status(404).json({ error: "Doctor not found" });
    if (!doctor.is_available) return res.status(409).json({ error: "Doctor is not available" });

    const hospital = db.prepare("SELECT name FROM hospitals WHERE id=?").get(doctor.hospital_id);
    const sessionId = `${doctorId}_${date}_${session}`;
    const patient   = db.prepare("SELECT name FROM users WHERE id=?").get(req.user.id);
    const id        = `b_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;

    let finalTokenNumber;

    // Everything in one transaction — atomic, no partial commits
    db.transaction(() => {
      // Fresh capacity check inside transaction (prevents race conditions)
      const count = db.stmts.countBookingsForSession.get(sessionId).c;
      if (count >= doctor.tokens_per_session)
        throw Object.assign(new Error("This session is fully booked"), { status: 409 });

      const dup = db.prepare(
        "SELECT id FROM bookings WHERE session_id=? AND patient_id=? AND status!='cancelled'"
      ).get(sessionId, req.user.id);
      if (dup)
        throw Object.assign(new Error("You already have a booking in this session"), { status: 409 });

      finalTokenNumber = count + 1;

      db.prepare(`
        INSERT INTO bookings
          (id, patient_id, patient_name, doctor_id, doctor_name, hospital_name,
           date, session, token_number, session_id, payment_done, status, phone, complaint)
        VALUES (?,?,?,?,?,?,?,?,?,?,1,'confirmed',?,?)
      `).run(
        id, req.user.id, patient?.name || "Unknown",
        doctorId, doctor.name, hospital?.name || "Unknown",
        date, session, finalTokenNumber, sessionId, phone, complaint
      );

      // Update or create token state
      const existing = db.stmts.getTokenState.get(sessionId);
      if (existing) {
        const statuses = JSON.parse(existing.token_statuses || "{}");
        statuses[finalTokenNumber] = "red";
        db.stmts.updateTokenState.run(
          JSON.stringify(statuses), existing.priority_slots,
          existing.current_token, existing.next_token, existing.is_closed, sessionId
        );
      } else {
        const statuses = JSON.stringify({ [finalTokenNumber]: "red" });
        db.prepare(
          "INSERT INTO token_states (session_id, doctor_id, date, session, token_statuses) VALUES (?,?,?,?,?)"
        ).run(sessionId, doctorId, date, session, statuses);
      }
    })();

    broadcast(sessionId, { type: "token_booked", tokenNumber: finalTokenNumber, sessionId });

    const booking = row2booking(db.prepare("SELECT * FROM bookings WHERE id=?").get(id));
    console.log(`[bookings] created id=${id} token=${finalTokenNumber} session=${sessionId}`);
    res.status(201).json(booking);

  } catch (err) {
    console.error("[bookings POST]", err.message);
    res.status(err.status || 500).json({ error: err.message });
  }
});

// ── PATCH booking status ──────────────────────────────────────────────────────
router.patch("/:id/status", requireDoctorOrAdmin, (req, res) => {
  try {
    const { status } = req.body;
    const valid = ["confirmed","completed","unvisited","cancelled"];
    if (!valid.includes(status))
      return res.status(400).json({ error: `Status must be one of: ${valid.join(", ")}` });

    const result = db.prepare("UPDATE bookings SET status=? WHERE id=?").run(status, req.params.id);
    if (result.changes === 0)
      return res.status(404).json({ error: "Booking not found" });

    res.json(row2booking(db.prepare("SELECT * FROM bookings WHERE id=?").get(req.params.id)));
  } catch (err) {
    console.error("[bookings PATCH]", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── GET stats ─────────────────────────────────────────────────────────────────
router.get("/stats/summary", requireAdmin, (req, res) => {
  try {
    res.json({
      totalHospitals: db.prepare("SELECT COUNT(*) as c FROM hospitals").get().c,
      totalDoctors:   db.prepare("SELECT COUNT(*) as c FROM doctors").get().c,
      totalPatients:  db.prepare("SELECT COUNT(*) as c FROM users WHERE role='patient'").get().c,
      totalBookings:  db.prepare("SELECT COUNT(*) as c FROM bookings").get().c,
      activeSessions: db.prepare(
        "SELECT COUNT(*) as c FROM token_states WHERE is_closed=0 AND current_token IS NOT NULL"
      ).get().c,
    });
  } catch (err) {
    console.error("[bookings stats]", err.message);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
