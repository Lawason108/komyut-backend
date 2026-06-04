'use strict';
/**
 * scripts/seed.js
 * Creates test accounts for development. Run after migration:
 *   node scripts/seed.js
 *
 * Accounts (all PIN = 1234):
 *   Super Admin  08000000000
 *   Ops Staff    08000000001  (operations role — limited access)
 *   Driver       08039876543  (approved + vehicle)
 *   Driver       08039876544  (pending verification)
 *   Member       08031234567  (₦5,000 balance)
 *   Member(fleet)08031234568
 */
require('dotenv').config();
const { Pool } = require('pg');
const bcrypt   = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const SEED_PIN = '1234';

const ACCOUNTS = [
  { role: 'admin',  name: 'Komyut Admin', phone: '08000000000', staff_role: 'super_admin' },
  { role: 'admin',  name: 'Tunde Ops',    phone: '08000000001', staff_role: 'operations' },
  { role: 'driver', name: 'Emeka Okafor', phone: '08039876543', verification_status: 'approved', verified: true,
    vehicle: { model: 'Toyota Corolla', plate: 'RV 248 KJA', color: 'Silver', capacity: 4, seat_preference: 3 } },
  { role: 'driver', name: 'Blessing Ade', phone: '08039876544', verification_status: 'pending' },
  { role: 'member', name: 'Chinedu Obi',  phone: '08031234567', balance: 5000 },
  { role: 'member', name: 'ACME Corp',    phone: '08031234568', user_type: 'fleet', company_name: 'ACME Logistics', balance: 20000 },
];

async function seed() {
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  });

  const pinHash = await bcrypt.hash(SEED_PIN, 12);

  for (const acc of ACCOUNTS) {
    const existing = await pool.query('SELECT id FROM users WHERE phone=$1', [acc.phone]);
    if (existing.rows.length > 0) {
      console.log(`⏭   ${acc.role} (${acc.phone}) already exists — skipping`);
      continue;
    }

    const id = uuidv4();
    await pool.query(
      `INSERT INTO users
         (id, role, name, phone, password_hash, wallet_balance, is_active,
          user_type, company_name, verification_status, staff_role)
       VALUES ($1,$2,$3,$4,$5,$6,true,$7,$8,$9,$10)`,
      [
        id, acc.role, acc.name, acc.phone, pinHash, acc.balance ?? 0,
        acc.user_type ?? 'normal', acc.company_name ?? null,
        acc.verification_status ?? (acc.role === 'driver' ? 'unsubmitted' : 'approved'),
        acc.staff_role ?? null,
      ]
    );

    if (acc.role === 'driver') {
      await pool.query(
        `INSERT INTO driver_status (driver_id, is_online, is_available) VALUES ($1, false, false)`,
        [id]
      );
      if (acc.vehicle) {
        await pool.query(
          `INSERT INTO driver_vehicles (driver_id, plate_number, model, color, capacity, seat_preference)
           VALUES ($1,$2,$3,$4,$5,$6)`,
          [id, acc.vehicle.plate, acc.vehicle.model, acc.vehicle.color, acc.vehicle.capacity, acc.vehicle.seat_preference]
        );
      }
    }

    console.log(`✅  ${acc.role.padEnd(6)} ${acc.name} (${acc.phone})${acc.staff_role ? ' · ' + acc.staff_role : ''}`);
  }

  await pool.end();
  console.log('\n🎉  Seed complete. All PINs = 1234\n');
  console.log('  Super Admin  08000000000');
  console.log('  Ops Staff    08000000001  (limited access)');
  console.log('  Driver       08039876543  (approved)');
  console.log('  Driver       08039876544  (pending verification)');
  console.log('  Member       08031234567  (₦5,000)');
  console.log('  Fleet Member 08031234568');
}

seed().catch(err => {
  console.error('❌  Seed failed:', err.message);
  process.exit(1);
});
