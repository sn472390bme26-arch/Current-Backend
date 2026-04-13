"use strict";
/**
 * sms.js — MSG91 OTP sender with retry + timeout
 *
 * ENV VARS:
 *   MSG91_AUTH_KEY    — your MSG91 API auth key
 *   MSG91_TEMPLATE_ID — OTP template ID from MSG91 dashboard
 *   MSG91_SENDER_ID   — 6-char sender (default: DOCBKD)
 */

const IS_DEV = !process.env.MSG91_AUTH_KEY;

function generateOTP() {
  // Cryptographically random 6-digit OTP
  const array = new Uint32Array(1);
  // Use Math.random as fallback since crypto.getRandomValues may not exist in all Node versions
  const rand = Math.floor(Math.random() * 900000) + 100000;
  return String(rand);
}

// Normalise phone → 91XXXXXXXXXX (no + sign, with country code)
function normalisePhone(raw) {
  const digits = String(raw).replace(/\D/g, "");
  if (digits.startsWith("91") && digits.length === 12) return digits;
  if (digits.length === 10) return `91${digits}`;
  if (digits.length === 11 && digits.startsWith("0")) return `91${digits.slice(1)}`;
  return digits;
}

// Fetch with timeout helper
async function fetchWithTimeout(url, opts, ms = 10000) {
  const ctrl = new AbortController();
  const id   = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal });
  } finally {
    clearTimeout(id);
  }
}

async function sendOTP(phone, otp, attempt = 1) {
  if (IS_DEV) {
    console.log(`\n📱 [SMS/DEV] OTP for +${phone} → ${otp}\n`);
    return;
  }

  const authKey    = process.env.MSG91_AUTH_KEY;
  const templateId = process.env.MSG91_TEMPLATE_ID;
  const senderId   = process.env.MSG91_SENDER_ID || "DOCBKD";

  if (!templateId) throw new Error("MSG91_TEMPLATE_ID is not set in environment variables.");

  try {
    const res = await fetchWithTimeout(
      "https://control.msg91.com/api/v5/otp",
      {
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
      },
      10_000 // 10s timeout per attempt
    );

    const data = await res.json().catch(() => ({}));

    if (!res.ok || data.type === "error") {
      throw new Error(data.message || `MSG91 error ${res.status}`);
    }

    console.log(`[SMS/MSG91] OTP sent to +${phone}`);
  } catch (err) {
    // Retry once on network/timeout errors
    if (attempt < 2 && (err.name === "AbortError" || err.message?.includes("fetch"))) {
      console.warn(`[SMS] Attempt ${attempt} failed, retrying...`);
      await new Promise(r => setTimeout(r, 2000));
      return sendOTP(phone, otp, attempt + 1);
    }

    if (err.name === "AbortError") {
      throw new Error("OTP service timed out. Please try again.");
    }
    throw err;
  }
}

module.exports = { sendOTP, generateOTP, normalisePhone, IS_DEV };
