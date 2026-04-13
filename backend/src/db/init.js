"use strict";
const Database = require("better-sqlite3");
const path = require("path");
const fs   = require("fs");
require("dotenv").config();

const DB_PATH = process.env.DB_PATH || "./data/doctor_booked.db";
const dir = path.dirname(DB_PATH);
if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

const db = new Database(DB_PATH);

// ── Performance & reliability pragmas ────────────────────────────────────────
db.pragma("journal_mode = WAL");      // concurrent reads during writes
db.pragma("busy_timeout = 10000");    // wait up to 10s before SQLITE_BUSY
db.pragma("synchronous = NORMAL");    // safe with WAL, much faster than FULL
db.pragma("foreign_keys = ON");       // enforce referential integrity
db.pragma("cache_size = -65536");     // 64MB page cache (reduces disk I/O)
db.pragma("temp_store = MEMORY");     // keep temp tables in RAM
db.pragma("mmap_size = 268435456");   // 256MB memory-mapped I/O
db.pragma("wal_autocheckpoint = 1000"); // checkpoint every 1000 pages

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    email       TEXT UNIQUE,
    name        TEXT,
    password    TEXT,
    role        TEXT NOT NULL CHECK(role IN ('patient','doctor','admin')),
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS hospitals (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    area        TEXT NOT NULL,
    address     TEXT,
    phone       TEXT,
    rating      REAL NOT NULL DEFAULT 4.0,
    gradient    TEXT NOT NULL DEFAULT 'from-slate-400 to-slate-600',
    photo_url   TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS doctors (
    id                  TEXT PRIMARY KEY,
    user_id             TEXT REFERENCES users(id) ON DELETE SET NULL,
    hospital_id         TEXT NOT NULL REFERENCES hospitals(id) ON DELETE CASCADE,
    code                TEXT UNIQUE NOT NULL,
    name                TEXT NOT NULL,
    specialty           TEXT NOT NULL,
    phone               TEXT,
    bio                 TEXT,
    photo               TEXT,
    price               REAL NOT NULL DEFAULT 10,
    consultation_fee    REAL NOT NULL DEFAULT 10,
    tokens_per_session  INTEGER NOT NULL DEFAULT 20,
    sessions            TEXT NOT NULL DEFAULT 'morning,afternoon',
    session_timings     TEXT,
    is_available        INTEGER NOT NULL DEFAULT 1,
    years_of_experience TEXT,
    education           TEXT,
    languages           TEXT,
    created_at          TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS bookings (
    id              TEXT PRIMARY KEY,
    patient_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    patient_name    TEXT NOT NULL,
    doctor_id       TEXT NOT NULL REFERENCES doctors(id) ON DELETE CASCADE,
    doctor_name     TEXT NOT NULL,
    hospital_name   TEXT NOT NULL,
    date            TEXT NOT NULL,
    session         TEXT NOT NULL,
    token_number    INTEGER NOT NULL,
    session_id      TEXT NOT NULL,
    payment_done    INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'confirmed'
                    CHECK(status IN ('confirmed','completed','unvisited','cancelled')),
    phone           TEXT,
    complaint       TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS token_states (
    session_id      TEXT PRIMARY KEY,
    doctor_id       TEXT NOT NULL,
    date            TEXT NOT NULL,
    session         TEXT NOT NULL,
    token_statuses  TEXT NOT NULL DEFAULT '{}',
    priority_slots  TEXT NOT NULL DEFAULT '{}',
    current_token   INTEGER,
    next_token      INTEGER,
    is_closed       INTEGER NOT NULL DEFAULT 0,
    cancelled_keys  TEXT NOT NULL DEFAULT '[]',
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- ── Indexes ───────────────────────────────────────────────────────────────
  CREATE INDEX IF NOT EXISTS idx_bookings_patient     ON bookings(patient_id);
  CREATE INDEX IF NOT EXISTS idx_bookings_session     ON bookings(session_id);
  CREATE INDEX IF NOT EXISTS idx_bookings_doctor      ON bookings(doctor_id);
  CREATE INDEX IF NOT EXISTS idx_bookings_date        ON bookings(date);
  CREATE INDEX IF NOT EXISTS idx_bookings_status      ON bookings(status);
  CREATE INDEX IF NOT EXISTS idx_doctors_hospital     ON doctors(hospital_id);
  CREATE INDEX IF NOT EXISTS idx_doctors_available    ON doctors(is_available);
  CREATE INDEX IF NOT EXISTS idx_token_states_doctor  ON token_states(doctor_id);
  CREATE INDEX IF NOT EXISTS idx_token_states_date    ON token_states(date);
  CREATE INDEX IF NOT EXISTS idx_users_role           ON users(role);
`);

// ── Pre-compile hot queries for maximum performance ───────────────────────────
// These are called on every request — compiling once at startup saves ~0.1ms each
db.stmts = {
  getTokenState:  db.prepare("SELECT * FROM token_states WHERE session_id=?"),
  updateTokenState: db.prepare(`
    UPDATE token_states SET token_statuses=?, priority_slots=?,
    current_token=?, next_token=?, is_closed=?, updated_at=datetime('now')
    WHERE session_id=?
  `),
  getBookingsForSession: db.prepare(
    "SELECT * FROM bookings WHERE session_id=? AND status!='cancelled' ORDER BY token_number ASC"
  ),
  countBookingsForSession: db.prepare(
    "SELECT COUNT(*) as c FROM bookings WHERE session_id=? AND payment_done=1 AND status!='cancelled'"
  ),
};

// ── Safe migrations — add new columns without breaking existing data ──────────
const safeAlter = (sql) => { try { db.prepare(sql).run(); } catch (_) {} };
safeAlter("ALTER TABLE users ADD COLUMN phone TEXT");
safeAlter("ALTER TABLE users ADD COLUMN phone_verified INTEGER NOT NULL DEFAULT 0");
safeAlter("ALTER TABLE bookings ADD COLUMN razorpay_order_id TEXT");
safeAlter("ALTER TABLE bookings ADD COLUMN razorpay_payment_id TEXT");

// OTP store table — holds pending phone verifications (expires in 10 min)
db.prepare(`
  CREATE TABLE IF NOT EXISTS otp_pending (
    id          TEXT PRIMARY KEY,
    phone       TEXT NOT NULL,
    otp         TEXT NOT NULL,
    context     TEXT NOT NULL,   -- 'signup' | 'google' | 'login'
    data        TEXT,            -- JSON: email, name, password_hash, etc
    expires_at  INTEGER NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
  )
`).run();

db.prepare(`CREATE INDEX IF NOT EXISTS idx_otp_phone ON otp_pending(phone)`).run();

console.log("✅  Database ready:", path.resolve(DB_PATH));
console.log("   WAL mode     :", db.pragma("journal_mode", { simple: true }));
console.log("   Busy timeout :", db.pragma("busy_timeout",  { simple: true }), "ms");
module.exports = db;
