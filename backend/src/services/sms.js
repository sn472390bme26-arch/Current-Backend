"use strict";

const IS_DEV = !process.env.MSG91_AUTH_KEY;
const INTEGRATED_NUM = "918072966876";
const NAMESPACE      = "530143de_af61_4573_8407_9afd9b2e279b";
const WA_API_URL     = "https://api.msg91.com/api/v5/whatsapp/whatsapp-outbound-message/bulk/";
const WA_TEMPLATE    = "otp_verification"; // we'll create this template

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
    console.log(`\n📱 [WhatsApp/DEV] OTP for +${phone} → ${otp}\n`);
    return;
  }

  const authKey = process.env.MSG91_AUTH_KEY;

  try {
    const res = await fetchWithTimeout(
      WA_API_URL,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "authkey": authKey,
        },
        body: JSON.stringify({
          integrated_number: INTEGRATED_NUM,
          content_type: "template",
          payload: {
            messaging_product: "whatsapp",
            type: "template",
            template: {
              name: WA_TEMPLATE,
              language: { code: "en", policy: "deterministic" },
              namespace: NAMESPACE,
              to_and_components: [
                {
                  to: [phone],
                  components: {
                    body_1: { type: "text", value: otp },
                  },
                },
              ],
            },
          },
        }),
      },
      10_000
    );

    const data = await res.json().catch(() => ({}));
    console.log(`[WhatsApp/OTP] Response:`, JSON.stringify(data));

    if (!res.ok) throw new Error(data.message || `MSG91 WhatsApp error ${res.status}`);
    console.log(`[WhatsApp/OTP] OTP sent to +${phone}`);
  } catch (err) {
    if (attempt < 2 && (err.name === "AbortError" || err.message?.includes("fetch"))) {
      console.warn(`[WhatsApp/OTP] Attempt ${attempt} failed, retrying...`);
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
