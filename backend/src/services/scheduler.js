"use strict";
const cron = require("node-cron");
const db = require("../db/init");
const { refundBooking } = require("../routes/payments");

// ── Runs every day at midnight ────────────────────────────────────────────────
// Finds all confirmed bookings whose date has passed and refunds them
function startScheduler() {
  cron.schedule("0 0 * * *", async () => {
    console.log("[Scheduler] Running midnight expired bookings cleanup...");
    try {
      const today = new Date().toISOString().split("T")[0]; // YYYY-MM-DD

      // Find all confirmed bookings where date is before today
      const expiredBookings = db.prepare(`
        SELECT id, session_id, date, patient_name, token_number
        FROM bookings
        WHERE status = 'confirmed'
          AND payment_done = 1
          AND date < ?
      `).all(today);

      if (expiredBookings.length === 0) {
        console.log("[Scheduler] No expired bookings found.");
        return;
      }

      console.log(`[Scheduler] Found ${expiredBookings.length} expired booking(s) — processing...`);

      // Mark all as unvisited first
      db.prepare(`
        UPDATE bookings
        SET status = 'unvisited'
        WHERE status = 'confirmed'
          AND payment_done = 1
          AND date < ?
      `).run(today);

      // Trigger refund for each
      for (const booking of expiredBookings) {
        console.log(`[Scheduler] Refunding expired booking ${booking.id} — ${booking.patient_name} token #${booking.token_number} on ${booking.date}`);
        await refundBooking(booking.id).catch((err) =>
          console.error(`[Scheduler] Refund failed for ${booking.id}:`, err.message)
        );
      }

      console.log(`[Scheduler] Done. Processed ${expiredBookings.length} expired booking(s).`);
    } catch (err) {
      console.error("[Scheduler] Error during cleanup:", err.message);
    }
  }, {
    timezone: "Asia/Kolkata" // IST midnight
  });

  console.log("[Scheduler] Midnight cleanup job scheduled (IST).");
}

module.exports = { startScheduler };
