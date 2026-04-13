"use strict";

const AUTH_KEY       = process.env.MSG91_AUTH_KEY || "";
const INTEGRATED_NUM = "918072966876";
const NAMESPACE      = "530143de_af61_4573_8407_9afd9b2e279b";
const API_URL        = "https://api.msg91.com/api/v5/whatsapp/whatsapp-outbound-message/bulk/";
const IS_DEV = !AUTH_KEY;

async function sendWhatsApp(phone, templateName, components, namespace) {
  if (IS_DEV) {
    console.log(`\n📱 [WhatsApp/DEV] To: +${phone} Template: ${templateName}\n`);
    return;
  }
  try {
    const res = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json", "authkey": AUTH_KEY },
      body: JSON.stringify({
        integrated_number: INTEGRATED_NUM,
        content_type: "template",
        payload: {
          messaging_product: "whatsapp",
          type: "template",
          template: {
            name: templateName,
            language: { code: "en", policy: "deterministic" },
            namespace: namespace || null,
            to_and_components: [{ to: [phone], components }],
          },
        },
      }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.message || `MSG91 error ${res.status}`);
    console.log(`[WhatsApp] Sent ${templateName} to +${phone}`);
  } catch (err) {
    console.error(`[WhatsApp] Failed ${templateName} to +${phone}:`, err.message);
  }
}

async function sendBookingConfirmation({ phone, patientName, doctorName, hospitalName, date, session, tokenNumber }) {
  if (!phone) return;
  const p = String(phone).replace(/\D/g, "");
  const fullPhone = p.startsWith("91") ? p : `91${p}`;
  await sendWhatsApp(fullPhone, "booking_confirmation", {
    body_1: { type: "text", value: patientName },
    body_2: { type: "text", value: doctorName },
    body_3: { type: "text", value: hospitalName },
    body_4: { type: "text", value: date },
    body_5: { type: "text", value: session.charAt(0).toUpperCase() + session.slice(1) },
    body_6: { type: "text", value: String(tokenNumber) },
  }, NAMESPACE);
}

async function sendTokenCalled({ phone, patientName, tokenNumber, doctorName, hospitalName }) {
  if (!phone) return;
  const p = String(phone).replace(/\D/g, "");
  const fullPhone = p.startsWith("91") ? p : `91${p}`;
  await sendWhatsApp(fullPhone, "token_called", {
    body_1: { type: "text", value: patientName },
    body_2: { type: "text", value: String(tokenNumber) },
    body_3: { type: "text", value: doctorName },
    body_4: { type: "text", value: hospitalName },
  }, null);
}

module.exports = { sendBookingConfirmation, sendTokenCalled };
