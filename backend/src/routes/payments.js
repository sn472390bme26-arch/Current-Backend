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

// Razorpay API call with timeout + retry
async function razorpayWithRetry(fn, attempts = 2) {
  for (let i = 1; i <= attempts; i++) {
    try {
      return await Promise.race([
        fn(),
        new Promise((_, rej) => setTimeout(() => rej(new Error("Razorpay timeout")), 15_000)),
      ]);
    } catch (err) {
      if (i === attempts) throw err;
      console.warn(`[Razorpay] Attempt ${i} failed: ${err.message} — retrying...`);
      await new Promise(r => setTimeout(r, 2000));
    }
  }
}

// ── POST /api/payments/create-order ──────────────────────────────────────────
router.post("/create-order", requireAuth, async (req, res) => {
  if (!ensureRazorpay(res)) return;
  try {
    const { doctorId, date, session, complaint = "", phone = "" } = req.body;
    if (!doctorId || !date || !session)
      return res.status(400).json({ error: "doctorId, date and session are required." });

    // Validate date format (YYYY-MM-DD)
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date))
      return res.status(400).json({ error: "Invalid date format. Use YYYY-MM-DD." });

    const doctor = db.prepare("SELECT * FROM doctors WHERE id=?").get(doctorId);
    if (!doctor)   return res.status(404).json({ error: "Doctor not found." });
    if (!doctor.is_available)
      return res.status(409).json({ error: "Doctor is not available." });

    const hospital  = db.prepare("SELECT name FROM hospitals WHERE id=?").get(doctor.hospital_id);
    const sessionId = `${doctorId}_${date}_${session}`;

    // Check capacity
    const count = db.stmts.countBookingsForSession.get(sessionId).c;
    if (count >= doctor.tokens_per_session)
      return res.status(409).json({ error: "This session is fully booked." });

    // Check duplicate booking
    const dup = db.prepare(
      "SELECT id FROM bookings WHERE session_id=? AND patient_id=? AND status!='cancelled'"
    ).get(sessionId, req.user.id);
    if (dup) return res.status(409).json({ error: "You already have a booking in this session." });

    const amountRupees = doctor.consultation_fee || doctor.price || 10;
    const amountPaise  = Math.round(amountRupees * 100);

    // Idempotency key — prevents duplicate orders on network retry
    const idempotencyKey = `${req.user.id}_${sessionId}_${Date.now()}`;

    const order = await razorpayWithRetry(() =>
      razorpay.orders.create({
        amount:   amountPaise,
        currency: "INR",
        receipt:  `rcpt_${Date.now()}`.slice(0, 40),
        notes: {
          doctorId,
          doctorName:   doctor.name,
          hospitalName: hospital?.name || "",
          date,
          session,
          patientId:    req.user.id,
          sessionId,
          complaint:    (complaint || "").slice(0, 200),
          phone:        (phone || "").slice(0, 20),
        },
      })
    );

    console.log(`[Razorpay] Order created: ${order.id} ₹${amountRupees} for ${req.user.id}`);
    res.json({
      orderId:      order.id,
      amount:       amountPaise,
      amountRupees,
      currency:     "INR",
      keyId:        KEY_ID,
      doctorName:   doctor.name,
      hospitalName: hospital?.name || "",
    });
  } catch (err) {
    console.error("[payments create-order]", err.message);
    if (err.message?.includes("timeout"))
      return res.status(504).json({ error: "Payment gateway timed out. Please try again." });
    res.status(500).json({ error: "Failed to create payment order. Please try again." });
  }
});

// ── POST /api/payments/verify ─────────────────────────────────────────────────
router.post("/verify", requireAuth, async (req, res) => {
  if (!ensureRazorpay(res)) return;
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature)
      return res.status(400).json({ error: "Missing payment verification fields." });

    // ── Idempotency — if booking already exists for this order, return it ────
    const existingBooking = db.prepare(
      "SELECT * FROM bookings WHERE razorpay_order_id=?"
    ).get(razorpay_order_id);
    if (existingBooking) {
      console.log(`[Razorpay] Duplicate verify for order ${razorpay_order_id} — returning existing booking`);
      return res.json({
        success: true,
        booking: formatBooking(existingBooking),
      });
    }

    // ── Verify HMAC-SHA256 signature ─────────────────────────────────────────
    const expectedSig = crypto
      .createHmac("sha256", KEY_SECRET)
      .update(`${razorpay_order_id}|${razorpay_payment_id}`)
      .digest("hex");

    // Constant-time comparison to prevent timing attacks
    const sigBuffer  = Buffer.from(razorpay_signature, "hex");
    const expBuffer  = Buffer.from(expectedSig, "hex");
    const sigValid   = sigBuffer.length === expBuffer.length &&
                       crypto.timingSafeEqual(sigBuffer, expBuffer);

    if (!sigValid) {
      console.error(`[Razorpay] Signature mismatch for order ${razorpay_order_id}`);
      return res.status(400).json({ error: "Payment verification failed. Please contact support." });
    }

    // ── Fetch order from Razorpay ─────────────────────────────────────────────
    const order = await razorpayWithRetry(() => razorpay.orders.fetch(razorpay_order_id));
    const notes = order.notes || {};

    const { doctorId, date, session, patientId, sessionId,
            doctorName, hospitalName, complaint = "", phone = "" } = notes;

    if (!doctorId || !date || !session || !patientId || !sessionId)
      return res.status(400).json({ error: "Invalid payment order data." });

    // Verify the patient matches
    if (patientId !== req.user.id)
      return res.status(403).json({ error: "Payment does not belong to this account." });

    const doctor  = db.prepare("SELECT * FROM doctors WHERE id=?").get(doctorId);
    const patient = db.prepare("SELECT * FROM users WHERE id=?").get(req.user.id);
    if (!doctor || !patient)
      return res.status(404).json({ error: "Doctor or patient not found." });

    // ── Create booking in a transaction (race-condition safe) ─────────────────
    let booking;
    db.transaction(() => {
      // Re-check capacity
      const freshCount = db.stmts.countBookingsForSession.get(sessionId).c;
      if (freshCount >= doctor.tokens_per_session)
        throw Object.assign(
          new Error("Session became fully booked during payment. You will be refunded within 5-7 business days."),
          { status: 409 }
        );

      // Re-check duplicate
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

    // Broadcast to WebSocket clients
    try {
      broadcast(sessionId, { type: "token_booked", tokenNumber: booking.token_number, sessionId });
    } catch (wsErr) {
      console.error("[payments] WS broadcast error:", wsErr.message);
      // Don't fail the request just because WS broadcast failed
    }

    res.json({ success: true, booking: formatBooking(booking) });
  } catch (err) {
    console.error("[payments verify]", err.message);
    if (err.message?.includes("timeout"))
      return res.status(504).json({ error: "Payment gateway timed out. Your payment may have gone through — check your bookings before trying again." });
    res.status(err.status || 500).json({ error: err.message });
  }
});

function formatBooking(b) {
  return {
    id: b.id, patientId: b.patient_id, patientName: b.patient_name,
    doctorId: b.doctor_id, doctorName: b.doctor_name,
    hospitalName: b.hospital_name, date: b.date,
    session: b.session, tokenNumber: b.token_number,
    sessionId: b.session_id, paymentDone: !!b.payment_done, status: b.status,
    phone: b.phone || "", complaint: b.complaint || "",
    createdAt: b.created_at,
  };
}

module.exports = router;
