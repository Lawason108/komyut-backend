'use strict';
/**
 * scripts/migrate.js
 * Applies schema.sql then migration_v3.sql to the connected database.
 * Safe to run multiple times (all statements use IF NOT EXISTS / additive ALTERs).
 *
 * Usage: node scripts/migrate.js
 */
require('dotenv').config();
const { Pool } = require('pg');
const fs       = require('fs');
const path     = require('path');

async function migrate() {
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  });

  const files = ['schema.sql', 'migration_v3.sql'];
  try {
    for (const file of files) {
      const full = path.join(__dirname, file);
      if (!fs.existsSync(full)) { console.log(`⏭   ${file} not found — skipping`); continue; }
      const sql = fs.readFileSync(full, 'utf8');
      console.log(`⏳  Applying ${file}...`);
      await pool.query(sql);
      console.log(`✅  ${file} applied.`);
    }
    console.log('\n🎉  Database is up to date.');
  } finally {
    await pool.end();
  }
}

migrate().catch(err => {
  console.error('❌  Migration failed:', err.message);
  process.exit(1);
});
