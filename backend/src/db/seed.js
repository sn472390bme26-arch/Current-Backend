"use strict";
require("dotenv").config();
const bcrypt = require("bcryptjs");
const db = require("./init");

const ADMIN_CODE = process.env.ADMIN_CODE || "ADMIN-001";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "Admin@123";

const existing = db.prepare("SELECT id FROM users WHERE role='admin' LIMIT 1").get();
if (existing) {
  console.log("ℹ️  Admin user already exists — skipping seed.");
  process.exit(0);
}

const hash = bcrypt.hashSync(ADMIN_PASSWORD, 12);
db.prepare(`
  INSERT INTO users (id, email, name, password, role)
  VALUES (?, ?, ?, ?, 'admin')
`).run("admin-001", null, "System Admin", hash);

console.log("✅  Admin seeded.");
console.log(`   Code    : ${ADMIN_CODE}`);
console.log(`   Password: ${ADMIN_PASSWORD}`);
console.log("   ⚠️  Change ADMIN_PASSWORD in .env before going to production!");
