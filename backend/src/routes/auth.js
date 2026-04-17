"use strict";

const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");
const { OAuth2Client } = require("google-auth-library");
const db = require("../db/init");
const { sendOTP, generateOTP, normalisePhone, IS_DEV } = require("../services/sms");

const router = express.Router();

const SECRET = process.env.JWT_SECRET || "fallback_dev_secret";
const EXPIRES = process.env.JWT_EXPIRES_IN || "7d";
const ADMIN_CODE = process.env.ADMIN_CODE || "ADMIN-001";
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5173";

const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

let mailTransporter = null;
try {
  const nodemailer = require("nodemailer");
  if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
    mailTransporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: String(process.env.SMTP_SECURE || "false") === "true",
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });
  }
} catch {
  mailTransporter = null;
}

function sign(payload) {
  return jwt.sign(payload, SECRET, { expiresIn: EXPIRES });
}

function validate(req, res) {
  const e = validationResult(req);
  if (!e.isEmpty()) {
    res.status(400).json({ error: e.array()[0].msg });
    return false;
  }
  return true;
}

function cleanOTPs() {
  db.prepare("DELETE FROM otp_pending WHERE expires_at < ?").run(Date.now());
}

function isLikelyEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(String(value || "").trim());
}

async function sendResetPasswordEmail(toEmail, name, resetLink) {
  const fromEmail =
    process.env.MAIL_FROM ||
    process.env.SMTP_USER ||
    "no-reply@doctorbooked.local";

  const safeName = name || "there";
  const subject = "Reset your Doctor Booked password";
  const text =
    `Hi ${safeName},\n\n` +
    `Use the link below to reset your password:\n${resetLink}\n\n` +
    `This link expires in 30 minutes.`;

  if (mailTransporter) {
    await mailTransporter.sendMail({
      from: fromEmail,
      to: toEmail,
      subject,
      text,
      html:
        `<p>Hi ${safeName},</p>` +
        `<p>Use the link below to reset your password:</p>` +
        `<p><a href="${resetLink}">${resetLink}</a></p>` +
        `<p>This link expires in 30 minutes.</p>`,
    });
    return;
  }

  // Dev fallback so flow still works without SMTP setup.
  console.log(`[auth forgot-password] SMTP not configured. Reset link for ${toEmail}: ${resetLink}`);
}

// ── Patient Signup — email/password ──────────────────────────────────────────
router.post(
  "/patient/signup",
  [
    body("name").trim().notEmpty().withMessage("Name is required"),
    body("password")
      .isLength({ min: 6 })
      .withMessage("Password must be at least 6 chars"),
    body("email").trim().isEmail().withMessage("Valid email is required"),
  ],
  async (req, res) => {
    if (!validate(req, res)) return;

    try {
      const name = String(req.body.name || "").trim();
      const email = String(req.body.email || "").trim().toLowerCase();
      const password = String(req.body.password || "");

      const exists = db
        .prepare("SELECT id FROM users WHERE email=? AND role='patient'")
        .get(email);
      if (exists) {
        return res.status(409).json({ error: "Email already registered. Please log in." });
      }

      const hash = bcrypt.hashSync(password, 12);
      const id = `p_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;

      db.prepare(
        `INSERT INTO users (id, email, name, password, role, phone_verified)
         VALUES (?, ?, ?, ?, 'patient', 0)`
      ).run(id, email, name, hash);

      const user = db.prepare("SELECT * FROM users WHERE id=?").get(id);

      return res.json({
        token: sign({ id: user.id, email: user.email, name: user.name, role: "patient" }),
        user: { id: user.id, email: user.email, name: user.name, role: "patient" },
        message: "Account created successfully.",
      });
    } catch (err) {
      console.error("[auth signup]", err.message);
      return res.status(500).json({ error: err.message || "Signup failed." });
    }
  }
);

// ── Patient Login — email/password (phone fallback supported) ────────────────
router.post(
  "/patient/login",
  [
    body("password").notEmpty().withMessage("Password is required"),
    body("email").optional().trim(),
    body("identifier").optional().trim(),
    body().custom((v) => {
      const id = String(v.email || v.identifier || "").trim();
      if (!id) throw new Error("Email is required");
      return true;
    }),
  ],
  async (req, res) => {
    if (!validate(req, res)) return;

    try {
      const identifier = String(req.body.email || req.body.identifier || "").trim();
      const password = String(req.body.password || "");

      let user = null;

      // Primary: email login
      if (isLikelyEmail(identifier)) {
        user = db
          .prepare("SELECT * FROM users WHERE email=? AND role='patient'")
          .get(identifier.toLowerCase());
      } else {
        // Backward compatibility: allow phone-based identifier
        try {
          const normPhone = normalisePhone(identifier);
          user = db
            .prepare("SELECT * FROM users WHERE phone=? AND role='patient'")
            .get(normPhone);
        } catch {
          user = null;
        }
      }

      if (!user) {
        return res.status(401).json({ error: "No account found with this email." });
      }
      if (!bcrypt.compareSync(password, user.password)) {
        return res.status(401).json({ error: "Incorrect password." });
      }

      return res.json({
        token: sign({ id: user.id, email: user.email, name: user.name, role: "patient" }),
        user: { id: user.id, email: user.email, name: user.name, role: "patient" },
      });
    } catch (err) {
      console.error("[auth login]", err.message);
      return res.status(500).json({ error: err.message || "Login failed." });
    }
  }
);

// ── Verify OTP — kept for backward compatibility ─────────────────────────────
router.post("/patient/verify-otp", async (req, res) => {
  try {
    cleanOTPs();

    const { otpId, otp } = req.body;
    if (!otpId || !otp) {
      return res.status(400).json({ error: "otpId and otp are required." });
    }

    const pending = db.prepare("SELECT * FROM otp_pending WHERE id=?").get(otpId);
    if (!pending) {
      return res
        .status(400)
        .json({ error: "OTP session not found or expired. Please request a new OTP." });
    }

    if (Date.now() > pending.expires_at) {
      db.prepare("DELETE FROM otp_pending WHERE id=?").run(otpId);
      return res.status(400).json({ error: "OTP has expired. Please request a new one." });
    }

    if (pending.attempts >= 5) {
      db.prepare("DELETE FROM otp_pending WHERE id=?").run(otpId);
      return res
        .status(429)
        .json({ error: "Too many wrong attempts. Please request a new OTP." });
    }

    if (pending.otp !== String(otp).trim()) {
      db.prepare("UPDATE otp_pending SET attempts=attempts+1 WHERE id=?").run(otpId);
      const left = 5 - (pending.attempts + 1);
      return res
        .status(400)
        .json({ error: `Incorrect OTP. ${left} attempt${left !== 1 ? "s" : ""} remaining.` });
    }

    const data = JSON.parse(pending.data || "{}");
    db.prepare("DELETE FROM otp_pending WHERE id=?").run(otpId);

    if (pending.context === "signup") {
      const { name, hash } = data;
      const id = `p_${pending.phone}`;
      db.prepare(
        `INSERT INTO users (id, email, name, password, role, phone, phone_verified)
         VALUES (?, NULL, ?, ?, 'patient', ?, 1)`
      ).run(id, name, hash, pending.phone);

      const user = db.prepare("SELECT * FROM users WHERE id=?").get(id);
      return res.json({
        token: sign({ id: user.id, name: user.name, phone: pending.phone, role: "patient" }),
        user: { id: user.id, name: user.name, phone: pending.phone, role: "patient" },
      });
    }

    if (pending.context === "login") {
      const user = db.prepare("SELECT * FROM users WHERE id=?").get(data.userId);
      if (!user) return res.status(404).json({ error: "Account not found." });

      return res.json({
        token: sign({ id: user.id, email: user.email, name: user.name, role: "patient" }),
        user: { id: user.id, email: user.email, name: user.name, role: "patient" },
      });
    }

    if (pending.context === "google") {
      const user = db.prepare("SELECT * FROM users WHERE id=?").get(data.userId);
      if (!user) return res.status(404).json({ error: "Account not found." });

      db.prepare("UPDATE users SET phone=?, phone_verified=1 WHERE id=?").run(
        pending.phone,
        user.id
      );

      return res.json({
        token: sign({ id: user.id, email: user.email, name: user.name, role: "patient" }),
        user: { id: user.id, email: user.email, name: user.name, role: "patient" },
      });
    }

    return res.status(400).json({ error: "Unknown OTP context." });
  } catch (err) {
    console.error("[auth verify-otp]", err.message);
    return res.status(500).json({ error: err.message });
  }
});

// ── Resend OTP — kept for backward compatibility ─────────────────────────────
router.post("/patient/resend-otp", async (req, res) => {
  try {
    const { otpId } = req.body;
    const pending = db.prepare("SELECT * FROM otp_pending WHERE id=?").get(otpId);
    if (!pending) {
      return res.status(400).json({ error: "OTP session not found. Please start over." });
    }

    const otp = generateOTP();
    const expiresAt = Date.now() + 10 * 60 * 1000;
    db.prepare(
      "UPDATE otp_pending SET otp=?, expires_at=?, attempts=0 WHERE id=?"
    ).run(otp, expiresAt, otpId);

    await sendOTP(pending.phone, otp);

    const resp = { success: true, message: "New OTP sent." };
    if (IS_DEV) resp.devOtp = otp;
    return res.json(resp);
  } catch (err) {
    console.error("[auth resend-otp]", err.message);
    return res.status(500).json({ error: err.message });
  }
});

// ── Google One Tap login ─────────────────────────────────────────────────────
router.post("/patient/google", async (req, res) => {
  try {
    if (!googleClient || !GOOGLE_CLIENT_ID) {
      return res.status(503).json({ error: "Google login is not configured." });
    }

    const { credential } = req.body;
    if (!credential) {
      return res.status(400).json({ error: "Google credential is required." });
    }

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();

    if (!payload?.email) {
      return res.status(401).json({ error: "Invalid Google credential." });
    }

    const email = String(payload.email).toLowerCase();
    const name = payload.name || email.split("@")[0];
    const googleId = String(payload.sub || "");

    let user = db
      .prepare("SELECT * FROM users WHERE email=? AND role='patient'")
      .get(email);

    if (!user) {
      const id = `p_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
      const hash = bcrypt.hashSync(`google_${googleId}_${Date.now()}`, 10);
      db.prepare(
        `INSERT INTO users (id, email, name, password, role, phone_verified)
         VALUES (?, ?, ?, ?, 'patient', 0)`
      ).run(id, email, name, hash);

      user = db.prepare("SELECT * FROM users WHERE id=?").get(id);
    }

    // No mandatory phone gate.
    return res.json({
      token: sign({ id: user.id, email: user.email, name: user.name, role: "patient" }),
      user: { id: user.id, email: user.email, name: user.name, role: "patient" },
    });
  } catch (err) {
    console.error("[auth google]", err.message);
    if (
      err.message?.includes("Token used too late") ||
      err.message?.includes("Invalid token")
    ) {
      return res.status(401).json({ error: "Google sign-in expired. Please try again." });
    }
    return res.status(500).json({ error: "Google login failed. Please try again." });
  }
});

// ── Google phone OTP endpoint kept for backward compatibility ────────────────
router.post("/patient/google-phone-otp", async (req, res) => {
  try {
    const { userId, phone } = req.body;
    if (!userId || !phone) {
      return res.status(400).json({ error: "userId and phone are required." });
    }

    const normPhone = normalisePhone(phone);
    const taken = db
      .prepare("SELECT id FROM users WHERE phone=? AND id!=?")
      .get(normPhone, userId);

    if (taken) {
      return res
        .status(409)
        .json({ error: "This phone is already registered to another account." });
    }

    const otp = generateOTP();
    const otpId = `otp_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    const expiresAt = Date.now() + 10 * 60 * 1000;

    db.prepare("DELETE FROM otp_pending WHERE phone=? AND context='google'").run(normPhone);
    db.prepare(
      `INSERT INTO otp_pending (id, phone, otp, context, data, expires_at)
       VALUES (?,?,?,'google',?,?)`
    ).run(otpId, normPhone, otp, JSON.stringify({ userId }), expiresAt);

    await sendOTP(normPhone, otp);

    const resp = {
      success: true,
      otpId,
      maskedPhone: `+${normPhone.slice(0, 2)}XXXXX${normPhone.slice(-4)}`,
      message: "OTP sent to your phone.",
    };
    if (IS_DEV) resp.devOtp = otp;
    return res.json(resp);
  } catch (err) {
    console.error("[auth google-phone-otp]", err.message);
    return res.status(500).json({ error: err.message });
  }
});

// ── Doctor login ─────────────────────────────────────────────────────────────
router.post(
  "/doctor/login",
  [body("code").trim().notEmpty(), body("phone").trim().notEmpty()],
  (req, res) => {
    if (!validate(req, res)) return;
    try {
      const { code, phone } = req.body;
      const doctor = db
        .prepare("SELECT * FROM doctors WHERE UPPER(code)=UPPER(?)")
        .get(String(code || "").trim());

      if (!doctor) {
        return res.status(401).json({ error: "Invalid access code. Please check with your admin." });
      }
      if (!(doctor.phone || "").trim()) {
        return res.status(401).json({ error: "No phone number set for this doctor. Contact admin." });
      }
      if (String(phone || "").trim() !== String(doctor.phone || "").trim()) {
        return res
          .status(401)
          .json({ error: "Incorrect password. Use your registered phone number." });
      }

      const payload = {
        id: `doc_${doctor.code}`,
        code: doctor.code,
        doctorId: doctor.id,
        role: "doctor",
      };

      return res.json({ token: sign(payload), user: payload });
    } catch (err) {
      console.error("[auth doctor/login]", err.message);
      return res.status(500).json({ error: err.message });
    }
  }
);

// ── Admin login ──────────────────────────────────────────────────────────────
router.post(
  "/admin/login",
  [body("code").trim().notEmpty(), body("password").notEmpty()],
  (req, res) => {
    if (!validate(req, res)) return;

    try {
      const { code, password } = req.body;

      if (String(code || "").toUpperCase() !== String(ADMIN_CODE).toUpperCase()) {
        return res.status(401).json({ error: "Invalid admin code" });
      }

      const ADMIN_PW = process.env.ADMIN_PASSWORD || "";
      if (ADMIN_PW && password === ADMIN_PW) {
        const payload = { id: "admin_1", role: "admin" };
        return res.json({ token: sign(payload), user: payload });
      }

      const admin = db.prepare("SELECT * FROM users WHERE role='admin' LIMIT 1").get();
      if (!admin || !bcrypt.compareSync(password, admin.password)) {
        return res.status(401).json({ error: "Invalid admin password" });
      }

      return res.json({
        token: sign({ id: admin.id, role: "admin" }),
        user: { id: admin.id, role: "admin" },
      });
    } catch (err) {
      console.error("[auth admin/login]", err.message);
      return res.status(500).json({ error: err.message });
    }
  }
);

// ── Verify token ─────────────────────────────────────────────────────────────
router.get("/me", (req, res) => {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "No token" });

  try {
    return res.json({ user: jwt.verify(token, SECRET) });
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
});

// ── Forgot Password Step 1: send reset email ────────────────────────────────
router.post(
  "/patient/forgot-password",
  [body("email").trim().isEmail().withMessage("Valid email is required")],
  async (req, res) => {
    if (!validate(req, res)) return;

    try {
      const email = String(req.body.email || "").trim().toLowerCase();
      const user = db
        .prepare("SELECT * FROM users WHERE email=? AND role='patient'")
        .get(email);

      // Always return success to avoid account enumeration.
      if (!user) {
        return res.json({
          success: true,
          message: "If this email exists, a reset link has been sent.",
        });
      }

      if (!mailTransporter) {
        return res.status(503).json({
          error: "Password reset email service is not configured. Please try again later.",
        });
      }

      if (!mailTransporter) {
        return res.status(503).json({
          error: "Password reset email service is not configured. Please try again later.",
        });
      }

      const resetToken = jwt.sign(
        { id: user.id, role: "patient", purpose: "reset-password" },
        SECRET,
        { expiresIn: process.env.RESET_TOKEN_EXPIRES_IN || "30m" }
      );

      const resetLink = `${FRONTEND_URL}/login?mode=reset&token=${encodeURIComponent(
        resetToken
      )}`;

      await sendResetPasswordEmail(user.email, user.name, resetLink);

      const response = {
        success: true,
        message: "If this email exists, a reset link has been sent.",
      };
      if (IS_DEV) response.resetLink = resetLink;

      return res.json(response);
    } catch (err) {
      console.error("[auth forgot-password]", err.message);
      return res
        .status(500)
        .json({ error: err.message || "Failed to send reset email." });
    }
  }
);

// ── Reset Password via signed token link ─────────────────────────────────────
router.post("/patient/reset-password-by-token", async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
      return res.status(400).json({ error: "token and newPassword are required." });
    }
    if (String(newPassword).length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters." });
    }

    let decoded = null;
    try {
      decoded = jwt.verify(token, SECRET);
    } catch {
      return res.status(400).json({ error: "Reset link is invalid or expired." });
    }

    if (!decoded || decoded.purpose !== "reset-password" || decoded.role !== "patient") {
      return res.status(400).json({ error: "Invalid reset token." });
    }

    const hash = bcrypt.hashSync(newPassword, 12);
    db.prepare("UPDATE users SET password=? WHERE id=?").run(hash, decoded.id);

    return res.json({
      success: true,
      message: "Password updated successfully. Please log in.",
    });
  } catch (err) {
    console.error("[auth reset-password-by-token]", err.message);
    return res
      .status(500)
      .json({ error: "Failed to reset password. Please try again." });
  }
});

// ── Legacy OTP reset endpoint (optional backward compatibility) ──────────────
router.post("/patient/reset-password", async (req, res) => {
  try {
    const { otpId, otp, newPassword } = req.body;
    if (!otpId || !otp || !newPassword) {
      return res
        .status(400)
        .json({ error: "otpId, otp and newPassword are required." });
    }
    if (String(newPassword).length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters." });
    }

    const pending = db
      .prepare("SELECT * FROM otp_pending WHERE id=? AND context='reset'")
      .get(otpId);
    if (!pending) {
      return res.status(400).json({ error: "OTP session not found or expired." });
    }

    if (Date.now() > pending.expires_at) {
      db.prepare("DELETE FROM otp_pending WHERE id=?").run(otpId);
      return res.status(400).json({ error: "OTP has expired. Please request a new one." });
    }

    if (pending.attempts >= 5) {
      db.prepare("DELETE FROM otp_pending WHERE id=?").run(otpId);
      return res
        .status(429)
        .json({ error: "Too many wrong attempts. Please request a new OTP." });
    }

    if (pending.otp !== String(otp).trim()) {
      db.prepare("UPDATE otp_pending SET attempts=attempts+1 WHERE id=?").run(otpId);
      const left = 5 - (pending.attempts + 1);
      return res
        .status(400)
        .json({ error: `Incorrect OTP. ${left} attempt${left !== 1 ? "s" : ""} remaining.` });
    }

    const data = JSON.parse(pending.data || "{}");
    db.prepare("DELETE FROM otp_pending WHERE id=?").run(otpId);

    const hash = bcrypt.hashSync(String(newPassword), 12);
    db.prepare("UPDATE users SET password=? WHERE id=?").run(hash, data.userId);

    return res.json({
      success: true,
      message: "Password updated successfully. Please log in.",
    });
  } catch (err) {
    console.error("[auth reset-password]", err.message);
    return res
      .status(500)
      .json({ error: "Failed to reset password. Please try again." });
  }
});

module.exports = router;