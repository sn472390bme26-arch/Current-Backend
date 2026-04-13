"use strict";
const express = require("express");
const bcrypt  = require("bcryptjs");
const jwt     = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");
const { OAuth2Client } = require("google-auth-library");
const db      = require("../db/init");
const { sendOTP, generateOTP, normalisePhone, IS_DEV } = require("../services/sms");

const router     = express.Router();
const SECRET     = process.env.JWT_SECRET     || "fallback_dev_secret";
const EXPIRES    = process.env.JWT_EXPIRES_IN || "7d";
const ADMIN_CODE = process.env.ADMIN_CODE     || "ADMIN-001";
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";

const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

function sign(payload) { return jwt.sign(payload, SECRET, { expiresIn: EXPIRES }); }
function validate(req, res) {
  const e = validationResult(req);
  if (!e.isEmpty()) { res.status(400).json({ error: e.array()[0].msg }); return false; }
  return true;
}
function cleanOTPs() {
  db.prepare("DELETE FROM otp_pending WHERE expires_at < ?").run(Date.now());
}

// ── Patient Signup — Step 1: send OTP ────────────────────────────────────────
router.post("/patient/signup",
  [
    body("name").trim().notEmpty().withMessage("Name is required"),
    body("password").isLength({ min: 6 }).withMessage("Password must be at least 6 chars"),
    body("phone").trim().notEmpty().withMessage("Phone number is required"),
  ],
  async (req, res) => {
    if (!validate(req, res)) return;
    try {
      const { name, password, phone } = req.body;
      const normPhone = normalisePhone(phone);

      if (db.prepare("SELECT id FROM users WHERE phone=? AND role='patient'").get(normPhone))
        return res.status(409).json({ error: "Phone number already registered. Please log in." });

      const otp       = generateOTP();
      const otpId     = `otp_${Date.now()}_${Math.random().toString(36).slice(2,7)}`;
      const expiresAt = Date.now() + 10 * 60 * 1000;
      const hash      = bcrypt.hashSync(password, 12);

      db.prepare("DELETE FROM otp_pending WHERE phone=? AND context='signup'").run(normPhone);
      db.prepare(`
        INSERT INTO otp_pending (id, phone, otp, context, data, expires_at)
        VALUES (?,?,?,'signup',?,?)
      `).run(otpId, normPhone, otp, JSON.stringify({ name, hash }), expiresAt);

      await sendOTP(normPhone, otp);

      const resp = { success: true, otpId, maskedPhone: `+${normPhone.slice(0,2)}XXXXX${normPhone.slice(-4)}`,
                     message: `OTP sent to your phone. Enter it to complete registration.` };
      if (IS_DEV) resp.devOtp = otp;
      res.json(resp);
    } catch (err) {
      console.error("[auth signup]", err.message);
      res.status(500).json({ error: err.message });
    }
  }
);

// ── Patient Login — Step 1: verify credentials, send OTP ─────────────────────
router.post("/patient/login",
  [body("phone").trim().notEmpty().withMessage("Phone number is required"), body("password").notEmpty()],
  async (req, res) => {
    if (!validate(req, res)) return;
    try {
      const { phone, password } = req.body;
      const normPhone = normalisePhone(phone);
      const user = db.prepare("SELECT * FROM users WHERE phone=? AND role='patient'").get(normPhone);
      if (!user) return res.status(401).json({ error: "No account found with this phone number." });
      if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: "Incorrect password." });

      // Old account without phone — log in directly
      if (!user.phone || !user.phone_verified) {
        return res.json({
          token: sign({ id: user.id, email: user.email, name: user.name, role: "patient" }),
          user:  { id: user.id, email: user.email, name: user.name, role: "patient" },
          needsPhone: true,
        });
      }

      const otp       = generateOTP();
      const otpId     = `otp_${Date.now()}_${Math.random().toString(36).slice(2,7)}`;
      const expiresAt = Date.now() + 10 * 60 * 1000;

      db.prepare("DELETE FROM otp_pending WHERE phone=? AND context='login'").run(user.phone);
      db.prepare(`
        INSERT INTO otp_pending (id, phone, otp, context, data, expires_at)
        VALUES (?,?,?,'login',?,?)
      `).run(otpId, user.phone, otp, JSON.stringify({ userId: user.id }), expiresAt);

      await sendOTP(user.phone, otp);

      const resp = { success: true, otpId,
                     maskedPhone: `+${user.phone.slice(0,2)}XXXXX${user.phone.slice(-4)}`,
                     message: `OTP sent to your registered phone.` };
      if (IS_DEV) resp.devOtp = otp;
      res.json(resp);
    } catch (err) {
      console.error("[auth login]", err.message);
      res.status(500).json({ error: err.message });
    }
  }
);

// ── Verify OTP — works for signup, login, google ──────────────────────────────
router.post("/patient/verify-otp", async (req, res) => {
  try {
    cleanOTPs();
    const { otpId, otp } = req.body;
    if (!otpId || !otp) return res.status(400).json({ error: "otpId and otp are required." });

    const pending = db.prepare("SELECT * FROM otp_pending WHERE id=?").get(otpId);
    if (!pending) return res.status(400).json({ error: "OTP session not found or expired. Please request a new OTP." });
    if (Date.now() > pending.expires_at) {
      db.prepare("DELETE FROM otp_pending WHERE id=?").run(otpId);
      return res.status(400).json({ error: "OTP has expired. Please request a new one." });
    }
    if (pending.attempts >= 5) {
      db.prepare("DELETE FROM otp_pending WHERE id=?").run(otpId);
      return res.status(429).json({ error: "Too many wrong attempts. Please request a new OTP." });
    }
    if (pending.otp !== otp.trim()) {
      db.prepare("UPDATE otp_pending SET attempts=attempts+1 WHERE id=?").run(otpId);
      const left = 5 - (pending.attempts + 1);
      return res.status(400).json({ error: `Incorrect OTP. ${left} attempt${left !== 1 ? "s" : ""} remaining.` });
    }

    const data = JSON.parse(pending.data || "{}");
    db.prepare("DELETE FROM otp_pending WHERE id=?").run(otpId);

    // ── Signup: create account ────────────────────────────────────────────────
    if (pending.context === "signup") {
      const { name, hash } = data;
      const id = `p_${pending.phone}`;
      db.prepare(`
        INSERT INTO users (id, email, name, password, role, phone, phone_verified)
        VALUES (?,NULL,?,?,'patient',?,1)
      `).run(id, name, hash, pending.phone);
      const user = db.prepare("SELECT * FROM users WHERE id=?").get(id);
      console.log(`[auth] signup verified: phone: ${pending.phone}`);
      return res.json({
        token: sign({ id: user.id, name: user.name, phone: pending.phone, role: "patient" }),
        user:  { id: user.id, name: user.name, phone: pending.phone, role: "patient" },
      });
    }

    // ── Login: return JWT ─────────────────────────────────────────────────────
    if (pending.context === "login") {
      const user = db.prepare("SELECT * FROM users WHERE id=?").get(data.userId);
      if (!user) return res.status(404).json({ error: "Account not found." });
      console.log(`[auth] login verified: ${user.email}`);
      return res.json({
        token: sign({ id: user.id, email: user.email, name: user.name, role: "patient" }),
        user:  { id: user.id, email: user.email, name: user.name, role: "patient" },
      });
    }

    // ── Google: save phone to account ─────────────────────────────────────────
    if (pending.context === "google") {
      const user = db.prepare("SELECT * FROM users WHERE id=?").get(data.userId);
      if (!user) return res.status(404).json({ error: "Account not found." });
      db.prepare("UPDATE users SET phone=?, phone_verified=1 WHERE id=?").run(pending.phone, user.id);
      console.log(`[auth] google phone verified: ${user.email} → ${pending.phone}`);
      return res.json({
        token: sign({ id: user.id, email: user.email, name: user.name, role: "patient" }),
        user:  { id: user.id, email: user.email, name: user.name, role: "patient" },
      });
    }

    res.status(400).json({ error: "Unknown OTP context." });
  } catch (err) {
    console.error("[auth verify-otp]", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── Resend OTP ────────────────────────────────────────────────────────────────
router.post("/patient/resend-otp", async (req, res) => {
  try {
    const { otpId } = req.body;
    const pending = db.prepare("SELECT * FROM otp_pending WHERE id=?").get(otpId);
    if (!pending) return res.status(400).json({ error: "OTP session not found. Please start over." });

    const otp       = generateOTP();
    const expiresAt = Date.now() + 10 * 60 * 1000;
    db.prepare("UPDATE otp_pending SET otp=?, expires_at=?, attempts=0 WHERE id=?").run(otp, expiresAt, otpId);

    await sendOTP(pending.phone, otp);

    const resp = { success: true, message: `New OTP sent.` };
    if (IS_DEV) resp.devOtp = otp;
    res.json(resp);
  } catch (err) {
    console.error("[auth resend-otp]", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── Google One Tap login ──────────────────────────────────────────────────────
router.post("/patient/google", async (req, res) => {
  try {
    if (!googleClient || !GOOGLE_CLIENT_ID)
      return res.status(503).json({ error: "Google login is not configured." });

    const { credential } = req.body;
    if (!credential) return res.status(400).json({ error: "Google credential is required." });

    const ticket  = await googleClient.verifyIdToken({ idToken: credential, audience: GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    if (!payload?.email) return res.status(401).json({ error: "Invalid Google credential." });

    const { email, name, sub: googleId } = payload;
    let user = db.prepare("SELECT * FROM users WHERE email=? AND role='patient'").get(email);

    if (!user) {
      const id   = `p_${email}`;
      const hash = bcrypt.hashSync(`google_${googleId}_${Date.now()}`, 10);
      db.prepare("INSERT INTO users (id, email, name, password, role, phone_verified) VALUES (?,?,?,?,'patient',0)")
        .run(id, email, name || email.split("@")[0], hash);
      user = db.prepare("SELECT * FROM users WHERE id=?").get(id);
      console.log(`[auth google] created: ${email}`);
    }

    if (user.phone && user.phone_verified) {
      return res.json({
        token: sign({ id: user.id, email: user.email, name: user.name, role: "patient" }),
        user:  { id: user.id, email: user.email, name: user.name, role: "patient" },
      });
    }

    return res.json({ needsPhone: true, userId: user.id, name: user.name, email: user.email });
  } catch (err) {
    console.error("[auth google]", err.message);
    if (err.message?.includes("Token used too late") || err.message?.includes("Invalid token"))
      return res.status(401).json({ error: "Google sign-in expired. Please try again." });
    res.status(500).json({ error: "Google login failed. Please try again." });
  }
});

// ── Google: send OTP to collected phone ──────────────────────────────────────
router.post("/patient/google-phone-otp", async (req, res) => {
  try {
    const { userId, phone } = req.body;
    if (!userId || !phone) return res.status(400).json({ error: "userId and phone are required." });
    const normPhone = normalisePhone(phone);

    const taken = db.prepare("SELECT id FROM users WHERE phone=? AND id!=?").get(normPhone, userId);
    if (taken) return res.status(409).json({ error: "This phone is already registered to another account." });

    const otp       = generateOTP();
    const otpId     = `otp_${Date.now()}_${Math.random().toString(36).slice(2,7)}`;
    const expiresAt = Date.now() + 10 * 60 * 1000;

    db.prepare("DELETE FROM otp_pending WHERE phone=? AND context='google'").run(normPhone);
    db.prepare(`
      INSERT INTO otp_pending (id, phone, otp, context, data, expires_at)
      VALUES (?,?,?,'google',?,?)
    `).run(otpId, normPhone, otp, JSON.stringify({ userId }), expiresAt);

    await sendOTP(normPhone, otp);

    const resp = { success: true, otpId,
                   maskedPhone: `+${normPhone.slice(0,2)}XXXXX${normPhone.slice(-4)}`,
                   message: `OTP sent to your phone.` };
    if (IS_DEV) resp.devOtp = otp;
    res.json(resp);
  } catch (err) {
    console.error("[auth google-phone-otp]", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── Doctor login ──────────────────────────────────────────────────────────────
router.post("/doctor/login",
  [body("code").trim().notEmpty(), body("phone").trim().notEmpty()],
  (req, res) => {
    if (!validate(req, res)) return;
    try {
      const { code, phone } = req.body;
      const doctor = db.prepare("SELECT * FROM doctors WHERE UPPER(code)=UPPER(?)").get(code.trim());
      if (!doctor) return res.status(401).json({ error: "Invalid access code. Please check with your admin." });
      if (!(doctor.phone || "").trim()) return res.status(401).json({ error: "No phone number set for this doctor. Contact admin." });
      if (phone.trim() !== (doctor.phone || "").trim())
        return res.status(401).json({ error: "Incorrect password. Use your registered phone number." });
      const payload = { id: `doc_${doctor.code}`, code: doctor.code, doctorId: doctor.id, role: "doctor" };
      res.json({ token: sign(payload), user: payload });
    } catch (err) {
      console.error("[auth doctor/login]", err.message);
      res.status(500).json({ error: err.message });
    }
  }
);

// ── Admin login ───────────────────────────────────────────────────────────────
router.post("/admin/login",
  [body("code").trim().notEmpty(), body("password").notEmpty()],
  (req, res) => {
    if (!validate(req, res)) return;
    try {
      const { code, password } = req.body;
      if (code.toUpperCase() !== ADMIN_CODE.toUpperCase())
        return res.status(401).json({ error: "Invalid admin code" });
      const admin = db.prepare("SELECT * FROM users WHERE role='admin' LIMIT 1").get();
      if (!admin || !bcrypt.compareSync(password, admin.password))
        return res.status(401).json({ error: "Invalid admin password" });
      res.json({ token: sign({ id: admin.id, role: "admin" }), user: { id: admin.id, role: "admin" } });
    } catch (err) {
      console.error("[auth admin/login]", err.message);
      res.status(500).json({ error: err.message });
    }
  }
);

// ── Verify token ──────────────────────────────────────────────────────────────
router.get("/me", (req, res) => {
  const header = req.headers.authorization || "";
  const token  = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "No token" });
  try { res.json({ user: jwt.verify(token, SECRET) }); }
  catch { res.status(401).json({ error: "Invalid or expired token" }); }
});

module.exports = router;
