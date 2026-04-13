"use strict";
/**
 * sms.js — MSG91 OTP sender
 *
 * ENV VARS (set on Railway):
 *   MSG91_AUTH_KEY    — your MSG91 API auth key
 *   MSG91_TEMPLATE_ID — OTP template ID from MSG91 dashboard
 *   MSG91_SENDER_ID   — 6-char sender (default: DOCBKD)
 *
 * If MSG91_AUTH_KEY is not set, runs in DEV mode:
 *   OTP is printed to Railway console and returned in the API response.
 *   NEVER deploy to production without setting MSG91_AUTH_KEY.
 */

const IS_DEV = !process.env.MSG91_AUTH_KEY;

function generateOTP() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

// Normalise phone → 91XXXXXXXXXX (no + sign, with country code)
function normalisePhone(raw) {
  const digits = String(raw).replace(/\D/g, "");
  if (digits.startsWith("91") && digits.length === 12) return digits;
  if (digits.length === 10) return `91${digits}`;
  return digits;
}

async function sendOTP(phone, otp) {
  if (IS_DEV) {
    console.log(`\n📱 [SMS/DEV] OTP for +${phone} → ${otp}\n`);
    return;
  }

  const authKey    = process.env.MSG91_AUTH_KEY;
  const templateId = process.env.MSG91_TEMPLATE_ID;
  const senderId   = process.env.MSG91_SENDER_ID || "DOCBKD";

  if (!templateId) throw new Error("MSG91_TEMPLATE_ID is not set in environment variables.");

  const res = await fetch("https://control.msg91.com/api/v5/otp", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "authkey": authKey,
    },
    body: JSON.stringify({
      template_id: templateId,
      mobile:      phone,
      authkey:     authKey,
      otp,
    }),
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok || data.type === "error") {
    throw new Error(data.message || `MSG91 error ${res.status}`);
  }

  console.log(`[SMS/MSG91] OTP sent to +${phone}`);
}

module.exports = { sendOTP, generateOTP, normalisePhone, IS_DEV };
