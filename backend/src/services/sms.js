"use strict";

const IS_DEV = !process.env.MSG91_AUTH_KEY;

function generateOTP() {
  return String(Math.floor(Math.random() * 900000) + 100000);
}

function normalisePhone(raw) {
  const digits = String(raw).replace(/\D/g, "");
  if (digits.startsWith("91") && digits.length === 12) return digits;
  if (digits.length === 10) return `91${digits}`;
  if (digits.length === 11 && digits.startsWith("0")) return `91${digits.slice(1)}`;
  return digits;
}

async function fetchWithTimeout(url, opts, ms = 10000) {
  const ctrl = new AbortController();
  const id = setTimeout(() => ctrl.abort(), ms);
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

  if (!templateId) throw new Error("MSG91_TEMPLATE_ID is not set.");

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
          otp:         otp,
          sender:      senderId,
        }),
      },
      10_000
    );

    const data = await res.json().catch(() => ({}));
    console.log(`[SMS/MSG91] Response:`, JSON.stringify(data));
    
    if (!res.ok || data.type === "error") {
      throw new Error(data.message || `MSG91 error ${res.status}`);
    }

    console.log(`[SMS/MSG91] OTP sent to +${phone}`);
  } catch (err) {
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
