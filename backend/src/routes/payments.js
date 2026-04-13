"use strict";
const express  = require("express");
const crypto   = require("crypto");
const Razorpay = require("razorpay");
const db       = require("../db/init");
const { requireAuth } = require("../middleware/auth");
const { broadcast }   = require("../services/ws");

const router = express.Router();

const KEY_ID     = process.env.RAZORPAY_KEY_ID     || "";
const KEY_SECRET = process.env.RAZORPAY_KEY_SECRET || "";

// Razorpay instance — only created if keys are configured
let razorpay = null;
if (KEY_ID && KEY_SECRET) {
  razorpay = new Razorpay({ key_id: KEY_ID, key_secret: KEY_SECRET });
  console.log("[Razorpay] Initialized — key:", KEY_ID.slice(0, 8) + "...");
} else {
  console.warn("[Razorpay] KEY_ID or KEY_SECRET not set — payment routes disabled");
}

function ensureRazorpay(res) {
  if (!razorpay) {
    res.status(503).json({ error: "Payment gateway is not configured. Contact support." });
    return false;
  }
  return true;
}

// ── POST /api/payments/create-order ──────────────────────────────────────────
// Creates a Razorpay order for a booking.
// Frontend calls this before opening the Razorpay checkout.
router.post("/create-order", requireAuth, async (req, res) => {
  if (!ensureRazorpay(res)) return;
  try {
    const { doctorId, date, session, complaint = "", phone = "" } = req.body;
    if (!doctorId || !date || !session)
      return res.status(400).json({ error: "doctorId, date and session are required." });

    const doctor = db.prepare("SELECT * FROM doctors WHERE id=?").get(doctorId);
    if (!doctor)   return res.status(404).json({ error: "Doctor not found." });
    if (!doctor.is_available)
      return res.status(409).json({ error: "Doctor is not available." });

    const hospital  = db.prepare("SELECT name FROM hospitals WHERE id=?").get(doctor.hospital_id);
    const sessionId = `${doctorId}_${date}_${session}`;

    // Check capacity
    const count = db.prepare(
      "SELECT COUNT(*) as c FROM bookings WHERE session_id=? AND payment_done=1 AND status!='cancelled'"
    ).get(sessionId).c;
    if (count >= doctor.tokens_per_session)
      return res.status(409).json({ error: "This session is fully booked." });

    // Check duplicate
    const dup = db.prepare(
      "SELECT id FROM bookings WHERE session_id=? AND patient_id=? AND status!='cancelled'"
    ).get(sessionId, req.user.id);
    if (dup) return res.status(409).json({ error: "You already have a booking in this session." });

    // Amount in paise (₹1 = 100 paise)
    const amountRupees = doctor.consultation_fee || doctor.price || 10;
    const amountPaise  = Math.round(amountRupees * 100);

    const order = await razorpay.orders.create({
      amount:   amountPaise,
      currency: "INR",
      receipt:  `rcpt_${Date.now()}`,
      notes: {
        doctorId,
        doctorName:  doctor.name,
        hospitalName: hospital?.name || "",
        date,
        session,
        patientId:   req.user.id,
        sessionId,
        complaint,
        phone,
      },
    });

    console.log(`[Razorpay] Order created: ${order.id} ₹${amountRupees} for ${req.user.id}`);
    res.json({
      orderId:     order.id,
      amount:      amountPaise,
      amountRupees,
      currency:    "INR",
      keyId:       KEY_ID,
      doctorName:  doctor.name,
      hospitalName: hospital?.name || "",
    });
  } catch (err) {
    console.error("[payments create-order]", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/payments/verify ─────────────────────────────────────────────────
// Called after Razorpay checkout succeeds on the frontend.
// Verifies the payment signature, then creates the booking in the DB.
router.post("/verify", requireAuth, async (req, res) => {
  if (!ensureRazorpay(res)) return;
  try {
    const {
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature,
    } = req.body;

    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature)
      return res.status(400).json({ error: "Missing payment verification fields." });

    // ── Verify signature (HMAC-SHA256) ──────────────────────────────────────
    const expectedSig = crypto
      .createHmac("sha256", KEY_SECRET)
      .update(`${razorpay_order_id}|${razorpay_payment_id}`)
      .digest("hex");

    if (expectedSig !== razorpay_signature) {
      console.error(`[Razorpay] Signature mismatch for order ${razorpay_order_id}`);
      return res.status(400).json({ error: "Payment verification failed. Please contact support." });
    }

    // ── Fetch order details from Razorpay to get booking metadata ────────────
    const order = await razorpay.orders.fetch(razorpay_order_id);
    const notes = order.notes || {};

    const { doctorId, date, session, patientId, sessionId,
            doctorName, hospitalName, complaint = "", phone = "" } = notes;

    // Verify the patient making the request matches the order
    if (patientId !== req.user.id)
      return res.status(403).json({ error: "Payment does not belong to this account." });

    const doctor  = db.prepare("SELECT * FROM doctors WHERE id=?").get(doctorId);
    const patient = db.prepare("SELECT * FROM users WHERE id=?").get(req.user.id);
    if (!doctor || !patient)
      return res.status(404).json({ error: "Doctor or patient not found." });

    // ── Create booking inside a transaction ───────────────────────────────────
    let booking;
    db.transaction(() => {
      // Re-check capacity (race condition protection)
      const freshCount = db.prepare(
        "SELECT COUNT(*) as c FROM bookings WHERE session_id=? AND payment_done=1 AND status!='cancelled'"
      ).get(sessionId).c;
      if (freshCount >= doctor.tokens_per_session)
        throw Object.assign(new Error("Session became fully booked during payment. You will be refunded."), { status: 409 });

      const dup = db.prepare(
        "SELECT id FROM bookings WHERE session_id=? AND patient_id=? AND status!='cancelled'"
      ).get(sessionId, req.user.id);
      if (dup)
        throw Object.assign(new Error("You already have a booking in this session."), { status: 409 });

      const tokenNumber = freshCount + 1;
      const bookingId   = `b_${Date.now()}_${Math.random().toString(36).slice(2,7)}`;

      db.prepare(`
        INSERT INTO bookings
          (id, patient_id, patient_name, doctor_id, doctor_name, hospital_name,
           date, session, token_number, session_id, payment_done, status,
           phone, complaint, razorpay_order_id, razorpay_payment_id)
        VALUES (?,?,?,?,?,?,?,?,?,?,1,'confirmed',?,?,?,?)
      `).run(
        bookingId, req.user.id, patient.name,
        doctorId, doctorName || doctor.name, hospitalName || "",
        date, session, tokenNumber, sessionId,
        phone, complaint,
        razorpay_order_id, razorpay_payment_id
      );

      // Update token state
      const existing = db.stmts.getTokenState.get(sessionId);
      if (existing) {
        const statuses = JSON.parse(existing.token_statuses || "{}");
        statuses[tokenNumber] = "red";
        db.stmts.updateTokenState.run(
          JSON.stringify(statuses), existing.priority_slots,
          existing.current_token, existing.next_token, existing.is_closed, sessionId
        );
      } else {
        db.prepare(
          "INSERT INTO token_states (session_id, doctor_id, date, session, token_statuses) VALUES (?,?,?,?,?)"
        ).run(sessionId, doctorId, date, session, JSON.stringify({ [tokenNumber]: "red" }));
      }

      booking = db.prepare("SELECT * FROM bookings WHERE id=?").get(bookingId);
      console.log(`[Razorpay] Booking confirmed: ${bookingId} token ${tokenNumber} order ${razorpay_order_id}`);
    })();

    broadcast(sessionId, { type: "token_booked", tokenNumber: booking.token_number, sessionId });

    res.json({
      success: true,
      booking: {
        id: booking.id, patientId: booking.patient_id, patientName: booking.patient_name,
        doctorId: booking.doctor_id, doctorName: booking.doctor_name,
        hospitalName: booking.hospital_name, date: booking.date,
        session: booking.session, tokenNumber: booking.token_number,
        sessionId: booking.session_id, paymentDone: true, status: booking.status,
        phone: booking.phone || "", complaint: booking.complaint || "",
        createdAt: booking.created_at,
      },
    });
  } catch (err) {
    console.error("[payments verify]", err.message);
    res.status(err.status || 500).json({ error: err.message });
  }
});

module.exports = router;
