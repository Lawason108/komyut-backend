'use strict';
require('dotenv').config();

const express    = require('express');
const http       = require('http');
const { Server } = require('socket.io');
const cors       = require('cors');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const crypto     = require('crypto');

const pool               = require('./db');
const { authenticate, authorize } = require('./middleware/auth');
const driverRoutes       = require('./routes/driver');
const adminRoutes        = require('./routes/admin');
const paymentRoutes      = require('./routes/payments');

// ═══════════════════════════════════════════
//  BOOT-TIME CHECKS
// ═══════════════════════════════════════════
const REQUIRED_ENV = ['DATABASE_URL', 'JWT_SECRET'];
const missing = REQUIRED_ENV.filter(k => !process.env[k]);
if (missing.length) {
  console.error('❌ Missing required env vars:', missing.join(', '));
  process.exit(1);
}

const JWT_SECRET = process.env.JWT_SECRET;
const NODE_ENV   = process.env.NODE_ENV || 'development';
const PORT       = parseInt(process.env.PORT, 10) || 3000;

// ═══════════════════════════════════════════
//  CORS ORIGINS
// ═══════════════════════════════════════════
const ALLOWED_ORIGINS = process.env.CORS_ORIGINS
  ? process.env.CORS_ORIGINS.split(',').map(o => o.trim())
  : [
      'http://localhost:3000',
      'http://localhost:4000',
      'http://localhost:5173',
      'http://localhost:5174',
      'http://127.0.0.1:5500',
      'null',           // file:// admin panel opened locally
    ];

// ═══════════════════════════════════════════
//  EXPRESS + HTTP
// ═══════════════════════════════════════════
const app    = express();
const server = http.createServer(app);

// ── Security headers ──────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false, // admin HTML is served stand-alone; CSP would block its CDN deps
}));

// ── CORS ──────────────────────────────────────────────────────────
app.use(cors({
  origin: function (origin, cb) {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    // In development, be permissive; in production, enforce
    if (NODE_ENV !== 'production') return cb(null, true);
    cb(new Error(`CORS: origin "${origin}" not allowed`));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// ── Rate limiting ─────────────────────────────────────────────────
const globalLimiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) || 15 * 60 * 1000,
  max:      parseInt(process.env.RATE_LIMIT_MAX, 10) || 200,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req, res) => res.status(429).json({ error: 'Too many requests. Slow down.' }),
});
app.use(globalLimiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max:      parseInt(process.env.AUTH_RATE_LIMIT_MAX, 10) || 10,
  handler: (_req, res) => res.status(429).json({ error: 'Too many login attempts. Try again later.' }),
});

// ── Paystack webhook: raw body BEFORE json parser ─────────────────
app.use('/api/payments/webhook', express.raw({ type: 'application/json' }));

// ── Body parsing ──────────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));

// ── Request logging (dev) ─────────────────────────────────────────
if (NODE_ENV !== 'production') {
  app.use((req, _res, next) => {
    console.log(`${req.method} ${req.path}`);
    next();
  });
}

// ═══════════════════════════════════════════
//  HEALTH CHECK
// ═══════════════════════════════════════════
app.get('/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, service: 'komyut-api', env: NODE_ENV, db: 'connected' });
  } catch {
    res.status(503).json({ ok: false, service: 'komyut-api', db: 'disconnected' });
  }
});

// ═══════════════════════════════════════════
//  AUTH ROUTES  (/api/auth/*)
//  Used by both the React web app (JWT pair)
//  and the admin HTML (single JWT_SECRET token)
// ═══════════════════════════════════════════

// ── Helpers ───────────────────────────────────────────────────────

// Shape a DB user row into the public user object the apps expect.
function publicUser(u) {
  return {
    id: u.id,
    name: u.name,
    phone: u.phone,
    role: u.role,
    email: u.email ?? undefined,
    photoUrl: u.photo_url ?? undefined,
    userType: u.user_type ?? 'normal',
    companyName: u.company_name ?? undefined,
    rating: u.rating != null ? Number(u.rating) : 5.0,
    verified: u.verification_status === 'approved' || u.verified === true,
    verificationStatus: u.verification_status ?? undefined,
    staffRole: u.staff_role ?? undefined,
  };
}

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: process.env.ACCESS_TOKEN_TTL || '15m',
  });
}

function signRefreshToken(payload) {
  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: process.env.REFRESH_TOKEN_TTL || '7d',
  });
}

// Track failed login attempts in-memory (simple; for production use Redis or DB)
const loginAttempts = new Map(); // phone → { count, firstAt }
const MAX_ATTEMPTS  = 5;
const LOCKOUT_MS    = 15 * 60 * 1000;

function isLockedOut(phone) {
  const rec = loginAttempts.get(phone);
  if (!rec) return false;
  if (Date.now() - rec.firstAt > LOCKOUT_MS) { loginAttempts.delete(phone); return false; }
  return rec.count >= MAX_ATTEMPTS;
}

function recordFailedAttempt(phone) {
  const rec = loginAttempts.get(phone) || { count: 0, firstAt: Date.now() };
  if (Date.now() - rec.firstAt > LOCKOUT_MS) { rec.count = 0; rec.firstAt = Date.now(); }
  rec.count++;
  loginAttempts.set(phone, rec);
}

function clearAttempts(phone) {
  loginAttempts.delete(phone);
}

// ── POST /api/auth/register ───────────────────────────────────────
app.post('/api/auth/register',
  authLimiter,
  [
    body('name').trim().notEmpty().withMessage('Name required'),
    body('phone').trim().notEmpty().withMessage('Phone required'),
    body('pin').isLength({ min: 4, max: 6 }).isNumeric().withMessage('PIN must be 4–6 digits'),
    body('role').isIn(['member', 'driver']).withMessage('Role must be member or driver'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { name, phone, pin, role, userType = 'normal', companyName } = req.body;
    const cleanPhone = phone.replace(/\s/g, '');

    // Fleet accounts require a company name; normal accounts: optional.
    if (userType === 'fleet' && !(companyName && String(companyName).trim())) {
      return res.status(400).json({ error: 'Company name is required for fleet accounts.' });
    }

    try {
      const existing = await pool.query('SELECT id FROM users WHERE phone = $1', [cleanPhone]);
      if (existing.rows.length > 0) {
        return res.status(409).json({ error: 'Phone number already registered.' });
      }

      const pinHash = await bcrypt.hash(pin, 12);
      const userId  = uuidv4();
      const verificationStatus = role === 'driver' ? 'unsubmitted' : 'approved';

      await pool.query('BEGIN');
      try {
        await pool.query(
          `INSERT INTO users
             (id, role, name, phone, password_hash, wallet_balance, is_active,
              user_type, company_name, verification_status)
           VALUES ($1,$2,$3,$4,$5,0,true,$6,$7,$8)`,
          [userId, role, name.trim(), cleanPhone, pinHash,
           userType, (companyName && String(companyName).trim()) || null, verificationStatus]
        );

        if (role === 'driver') {
          await pool.query(
            `INSERT INTO driver_status (driver_id, is_online, is_available) VALUES ($1, false, false)`,
            [userId]
          );
        }

        await pool.query('COMMIT');
      } catch (e) {
        await pool.query('ROLLBACK');
        throw e;
      }

      const user = (await pool.query(`SELECT * FROM users WHERE id = $1`, [userId])).rows[0];

      const accessToken  = signToken({ id: user.id, role: user.role });
      const refreshToken = signRefreshToken({ id: user.id, role: user.role });

      res.status(201).json({
        user:   publicUser(user),
        tokens: { accessToken, refreshToken },
      });
    } catch (err) {
      console.error('Register error:', err);
      res.status(500).json({ error: 'Registration failed.' });
    }
  }
);

// ── POST /api/auth/login ──────────────────────────────────────────
app.post('/api/auth/login',
  authLimiter,
  [
    body('phone').trim().notEmpty().withMessage('Phone required'),
    body('pin').notEmpty().withMessage('PIN required'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { phone, pin } = req.body;
    const cleanPhone = phone.replace(/\s/g, '');

    if (isLockedOut(cleanPhone)) {
      return res.status(429).json({ error: 'Too many failed attempts. Try again in 15 minutes.' });
    }

    try {
      const result = await pool.query(`SELECT * FROM users WHERE phone = $1`, [cleanPhone]);

      const user = result.rows[0];

      // Always run bcrypt to prevent user-enumeration via timing
      const dummyHash  = '$2b$12$invalidhashpadding.fortiminguniformity00000000000000000000';
      const hashToTest = user ? user.password_hash : dummyHash;
      const match      = await bcrypt.compare(pin, hashToTest);

      if (!user || !user.is_active || user.is_blocked || !match) {
        recordFailedAttempt(cleanPhone);
        return res.status(401).json({ error: 'Invalid phone or PIN.' });
      }

      clearAttempts(cleanPhone);

      const accessToken  = signToken({ id: user.id, role: user.role });
      const refreshToken = signRefreshToken({ id: user.id, role: user.role });

      res.json({
        user:   publicUser(user),
        tokens: { accessToken, refreshToken },
      });
    } catch (err) {
      console.error('Login error:', err);
      res.status(500).json({ error: 'Login failed.' });
    }
  }
);

// ── POST /api/auth/refresh ────────────────────────────────────────
app.post('/api/auth/refresh', async (req, res) => {
  const { refreshToken } = req.body || {};
  if (!refreshToken) return res.status(401).json({ error: 'Refresh token required.' });

  try {
    const decoded = jwt.verify(refreshToken, JWT_SECRET);
    // Confirm user still exists and is active
    const result = await pool.query('SELECT id, role, is_active FROM users WHERE id = $1', [decoded.id]);
    const user = result.rows[0];
    if (!user || !user.is_active) return res.status(401).json({ error: 'User not found or deactivated.' });

    const accessToken  = signToken({ id: user.id, role: user.role });
    const newRefresh   = signRefreshToken({ id: user.id, role: user.role });
    res.json({ tokens: { accessToken, refreshToken: newRefresh } });
  } catch {
    res.status(401).json({ error: 'Invalid or expired refresh token.' });
  }
});

// ── GET /api/auth/me ──────────────────────────────────────────────
app.get('/api/auth/me', authenticate, async (req, res) => {
  const r = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
  if (!r.rows[0]) return res.status(404).json({ error: 'User not found.' });
  res.json({ user: publicUser(r.rows[0]) });
});

// ── POST /api/auth/logout ─────────────────────────────────────────
app.post('/api/auth/logout', authenticate, (_req, res) => {
  res.json({ ok: true });
});

// ── POST /api/auth/admin-login ────────────────────────────────────
// Used by the admin HTML panel after local TOTP verification passes.
// Accepts {phone, pin} OR {email, password} for backward compatibility.
app.post('/api/auth/admin-login',
  authLimiter,
  async (req, res) => {
    // Support both formats
    const phone    = (req.body.phone || '').replace(/\s/g, '');
    const pin      = req.body.pin || req.body.password || '';

    if (!phone || !pin) {
      return res.status(400).json({ error: 'Phone and PIN required.' });
    }

    try {
      const result = await pool.query(
        `SELECT id, role, name, phone, password_hash, is_active FROM users
         WHERE phone=$1 AND role='admin'`,
        [phone]
      );
      const user = result.rows[0];
      const dummyHash = '$2b$12$invalidhashpadding.fortiminguniformity00000000000000000000';
      const match = await bcrypt.compare(pin, user ? user.password_hash : dummyHash);

      if (!user || !user.is_active || !match) {
        return res.status(401).json({ error: 'Invalid credentials.' });
      }

      const token = signToken({ id: user.id, role: user.role });
      res.json({
        token,
        admin: { id: user.id, name: user.name, phone: user.phone, role: user.role },
      });
    } catch (err) {
      console.error('Admin login error:', err);
      res.status(500).json({ error: 'Login failed.' });
    }
  }
);

// ── POST /api/auth/change-pin ─────────────────────────────────────
app.post('/api/auth/change-pin',
  authenticate,
  [
    body('currentPin').notEmpty(),
    body('newPin').isLength({ min: 4, max: 6 }).isNumeric(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { currentPin, newPin } = req.body;
    try {
      const result = await pool.query('SELECT password_hash FROM users WHERE id = $1', [req.user.id]);
      const match  = await bcrypt.compare(currentPin, result.rows[0].password_hash);
      if (!match) return res.status(401).json({ error: 'Current PIN is incorrect.' });

      const newHash = await bcrypt.hash(newPin, 12);
      await pool.query('UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2', [newHash, req.user.id]);
      res.json({ ok: true });
    } catch (err) {
      console.error('Change PIN error:', err);
      res.status(500).json({ error: 'Failed to change PIN.' });
    }
  }
);

// ═══════════════════════════════════════════
//  ROUTE MODULES
// ═══════════════════════════════════════════
app.use('/api/driver',   driverRoutes);
app.use('/api/admin',    adminRoutes);
app.use('/api/payments', paymentRoutes);

// ═══════════════════════════════════════════
//  MEMBER TRIP ROUTES  (/api/trips/*)
// ═══════════════════════════════════════════

// GET /api/trips/active — member's current active trip
app.get('/api/trips/active', authenticate, authorize('member'), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT t.*,
              u.name AS driver_name, u.phone AS driver_phone,
              ll.lat AS driver_lat, ll.lng AS driver_lng
       FROM trips t
       LEFT JOIN users u ON t.driver_id = u.id
       LEFT JOIN live_locations ll ON t.driver_id = ll.driver_id
       WHERE t.member_id = $1 AND t.status IN ('pending','accepted','ongoing')
       ORDER BY t.created_at DESC LIMIT 1`,
      [req.user.id]
    );
    res.json({ trip: result.rows[0] || null });
  } catch (err) {
    console.error('Active trip error:', err);
    res.status(500).json({ error: 'Failed to fetch active trip.' });
  }
});

// POST /api/trips — member books a trip
app.post('/api/trips',
  authenticate, authorize('member'),
  [
    body('pickup_address').trim().notEmpty(),
    body('pickup_lat').isFloat(),
    body('pickup_lng').isFloat(),
    body('dropoff_address').trim().notEmpty(),
    body('dropoff_lat').isFloat(),
    body('dropoff_lng').isFloat(),
    body('passenger_count').isInt({ min: 1, max: 10 }).optional(),
    body('fare').isFloat({ min: 1 }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const {
      pickup_address, pickup_lat, pickup_lng,
      dropoff_address, dropoff_lat, dropoff_lng,
      passenger_count = 1, fare,
    } = req.body;

    // Check no active trip already
    const activeCheck = await pool.query(
      `SELECT id FROM trips WHERE member_id = $1 AND status IN ('pending','accepted','ongoing')`,
      [req.user.id]
    );
    if (activeCheck.rows.length > 0) {
      return res.status(409).json({ error: 'You already have an active trip.' });
    }

    // Check sufficient wallet balance
    const walletResult = await pool.query('SELECT wallet_balance FROM users WHERE id = $1', [req.user.id]);
    const balance = parseFloat(walletResult.rows[0].wallet_balance);
    if (balance < fare) {
      return res.status(402).json({ error: `Insufficient balance. You need ₦${fare}, you have ₦${balance.toFixed(2)}.` });
    }

    const verificationCode = Math.floor(1000 + Math.random() * 9000);
    const tripId = uuidv4();

    try {
      await pool.query(
        `INSERT INTO trips (id, member_id, status, verification_code, fare, passenger_count,
          pickup_address, pickup_lat, pickup_lng,
          dropoff_address, dropoff_lat, dropoff_lng)
         VALUES ($1,$2,'pending',$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        [tripId, req.user.id, verificationCode, fare, passenger_count,
         pickup_address, pickup_lat, pickup_lng,
         dropoff_address, dropoff_lat, dropoff_lng]
      );

      const trip = (await pool.query('SELECT * FROM trips WHERE id = $1', [tripId])).rows[0];

      // Notify available drivers via socket
      io.to('drivers_online').emit('trip:new_request', {
        tripId: trip.id,
        memberId: req.user.id,
        memberName: req.user.name,
        pickup: { address: pickup_address, lat: pickup_lat, lng: pickup_lng },
        dropoff: { address: dropoff_address, lat: dropoff_lat, lng: dropoff_lng },
        fare, passengerCount: passenger_count,
        verificationCode,
      });

      res.status(201).json({ trip, verificationCode });
    } catch (err) {
      console.error('Book trip error:', err);
      res.status(500).json({ error: 'Failed to book trip.' });
    }
  }
);

// GET /api/trips/history — member trip history
app.get('/api/trips/history', authenticate, async (req, res) => {
  const { limit = 20, offset = 0 } = req.query;
  const col = req.user.role === 'driver' ? 'driver_id' : 'member_id';
  try {
    const result = await pool.query(
      `SELECT t.*,
              m.name AS member_name,
              d.name AS driver_name
       FROM trips t
       JOIN users m ON t.member_id = m.id
       LEFT JOIN users d ON t.driver_id = d.id
       WHERE t.${col} = $1
       ORDER BY t.created_at DESC
       LIMIT $2 OFFSET $3`,
      [req.user.id, parseInt(limit), parseInt(offset)]
    );
    res.json({ trips: result.rows });
  } catch (err) {
    console.error('Trip history error:', err);
    res.status(500).json({ error: 'Failed to fetch trip history.' });
  }
});

// DELETE /api/trips/:tripId — member cancels a pending trip
app.delete('/api/trips/:tripId', authenticate, authorize('member'), async (req, res) => {
  const { tripId } = req.params;
  const { reason } = req.body || {};
  try {
    const tripResult = await pool.query(
      `SELECT * FROM trips WHERE id = $1 AND member_id = $2 AND status IN ('pending','accepted')`,
      [tripId, req.user.id]
    );
    if (tripResult.rows.length === 0) {
      return res.status(404).json({ error: 'Trip not found or cannot be cancelled.' });
    }

    await pool.query(
      `UPDATE trips SET status='cancelled', cancelled_at=NOW(),
       cancellation_reason=$1, updated_at=NOW() WHERE id=$2`,
      [reason || 'Cancelled by passenger', tripId]
    );

    // Free driver if one was assigned
    const trip = tripResult.rows[0];
    if (trip.driver_id) {
      await pool.query(
        `UPDATE driver_status SET is_available=true, current_trip_id=NULL WHERE driver_id=$1`,
        [trip.driver_id]
      );
      io.to(`user_${trip.driver_id}`).emit('trip:cancelled', { tripId, reason });
    }

    res.json({ ok: true });
  } catch (err) {
    console.error('Cancel trip error:', err);
    res.status(500).json({ error: 'Failed to cancel trip.' });
  }
});

// ── Shared trip status (member + driver) ──────────────────────────
app.get('/api/trips/:tripId', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT t.*,
              m.name AS member_name, m.phone AS member_phone,
              d.name AS driver_name, d.phone AS driver_phone,
              ll.lat AS driver_lat, ll.lng AS driver_lng
       FROM trips t
       JOIN users m ON t.member_id = m.id
       LEFT JOIN users d ON t.driver_id = d.id
       LEFT JOIN live_locations ll ON t.driver_id = ll.driver_id
       WHERE t.id = $1`,
      [req.params.tripId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Trip not found.' });

    const trip = result.rows[0];
    // Only allow member, assigned driver, or admin to see trip
    const allowed = req.user.role === 'admin'
      || trip.member_id === req.user.id
      || trip.driver_id === req.user.id;
    if (!allowed) return res.status(403).json({ error: 'Forbidden.' });

    res.json({ trip });
  } catch (err) {
    console.error('Get trip error:', err);
    res.status(500).json({ error: 'Failed to fetch trip.' });
  }
});

// ── In-trip rating (member rates driver after trip) ───────────────
app.post('/api/trips/:tripId/rate',
  authenticate, authorize('member'),
  [
    body('rating').isInt({ min: 1, max: 5 }),
    body('comment').optional().trim().isLength({ max: 500 }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { rating, comment } = req.body;
    const { tripId } = req.params;

    try {
      const tripCheck = await pool.query(
        `SELECT driver_id FROM trips WHERE id=$1 AND member_id=$2 AND status='completed'`,
        [tripId, req.user.id]
      );
      if (tripCheck.rows.length === 0) {
        return res.status(404).json({ error: 'Trip not found or not eligible for rating.' });
      }

      await pool.query(
        `INSERT INTO driver_ratings (trip_id, driver_id, member_id, rating, comment)
         VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (trip_id) DO UPDATE SET rating=$4, comment=$5, created_at=NOW()`,
        [tripId, tripCheck.rows[0].driver_id, req.user.id, rating, comment || null]
      );

      res.status(201).json({ ok: true });
    } catch (err) {
      console.error('Rating error:', err);
      res.status(500).json({ error: 'Failed to submit rating.' });
    }
  }
);

// ── Trip messages ─────────────────────────────────────────────────
app.get('/api/trips/:tripId/messages', authenticate, async (req, res) => {
  const { tripId } = req.params;
  try {
    const tripCheck = await pool.query(`SELECT member_id, driver_id FROM trips WHERE id=$1`, [tripId]);
    if (tripCheck.rows.length === 0) return res.status(404).json({ error: 'Trip not found.' });
    const t = tripCheck.rows[0];
    const ok = req.user.role === 'admin' || t.member_id === req.user.id || t.driver_id === req.user.id;
    if (!ok) return res.status(403).json({ error: 'Forbidden.' });

    const result = await pool.query(
      `SELECT tm.*, u.name AS sender_name FROM trip_messages tm
       JOIN users u ON tm.sender_id = u.id
       WHERE tm.trip_id=$1 ORDER BY tm.created_at ASC`,
      [tripId]
    );
    res.json({ messages: result.rows });
  } catch (err) {
    console.error('Messages error:', err);
    res.status(500).json({ error: 'Failed to fetch messages.' });
  }
});

// ═══════════════════════════════════════════
//  PROFILE ROUTES  (/api/profile/*)
// ═══════════════════════════════════════════

app.get('/api/profile', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, role, name, phone, wallet_balance, is_active, created_at FROM users WHERE id=$1`,
      [req.user.id]
    );
    res.json({ user: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch profile.' });
  }
});

app.patch('/api/profile', authenticate,
  [body('name').optional().trim().notEmpty()],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const { name } = req.body;
    try {
      const result = await pool.query(
        `UPDATE users SET name=COALESCE($1, name), updated_at=NOW() WHERE id=$2
         RETURNING id, role, name, phone, wallet_balance, is_active`,
        [name || null, req.user.id]
      );
      res.json({ user: result.rows[0] });
    } catch (err) {
      res.status(500).json({ error: 'Failed to update profile.' });
    }
  }
);

// ═══════════════════════════════════════════
//  WALLET ROUTES  (/api/wallet/*)
// ═══════════════════════════════════════════

app.get('/api/wallet', authenticate, async (req, res) => {
  try {
    const balRes = await pool.query('SELECT wallet_balance FROM users WHERE id=$1', [req.user.id]);
    const txRes  = await pool.query(
      `SELECT id, type AS kind, amount, balance_after, description AS label,
              reference_code AS reference, created_at AS date
       FROM wallet_transactions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50`,
      [req.user.id]
    );
    res.json({
      balance:      parseFloat(balRes.rows[0]?.wallet_balance || 0),
      bank:         '0000000000',   // placeholder until bank details feature is built
      pending:      0,
      transactions: txRes.rows,
    });
  } catch (err) {
    console.error('Wallet error:', err);
    res.status(500).json({ error: 'Failed to fetch wallet.' });
  }
});

// Top-up (non-Paystack direct credit — dev/test mode)
app.post('/api/wallet/topup',
  authenticate, authorize('member'),
  [body('amount').isFloat({ min: 100, max: 1000000 })],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { amount } = req.body;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const cur = await client.query('SELECT wallet_balance FROM users WHERE id=$1 FOR UPDATE', [req.user.id]);
      const newBalance = parseFloat(cur.rows[0].wallet_balance) + parseFloat(amount);
      await client.query('UPDATE users SET wallet_balance=$1 WHERE id=$2', [newBalance, req.user.id]);
      const ref = 'TOP-' + uuidv4().split('-')[0].toUpperCase();
      await client.query(
        `INSERT INTO wallet_transactions (user_id,type,amount,balance_after,description,reference_code)
         VALUES ($1,'credit',$2,$3,'Direct top-up (test mode)',$4)`,
        [req.user.id, amount, newBalance, ref]
      );
      await client.query('COMMIT');

      // Update connected member's wallet display
      io.to(`user_${req.user.id}`).emit('wallet:updated', { balance: newBalance });

      res.json({ ok: true, balance: newBalance });
    } catch (err) {
      await client.query('ROLLBACK');
      console.error('Topup error:', err);
      res.status(500).json({ error: 'Top-up failed.' });
    } finally { client.release(); }
  }
);

// Withdraw (driver)
app.post('/api/wallet/withdraw',
  authenticate, authorize('driver'),
  [body('amountNaira').isFloat({ min: 100 })],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const amountNaira = parseFloat(req.body.amountNaira);
    const fee   = Math.round(amountNaira * 0.02 * 100) / 100;
    const net   = amountNaira - fee;
    const client = await pool.connect();

    try {
      await client.query('BEGIN');
      const walletResult = await client.query(
        'SELECT wallet_balance FROM users WHERE id=$1 FOR UPDATE', [req.user.id]
      );
      const balance = parseFloat(walletResult.rows[0].wallet_balance);
      if (balance < amountNaira) {
        await client.query('ROLLBACK');
        return res.status(400).json({ error: 'Insufficient balance.' });
      }
      const newBalance = balance - amountNaira;
      await client.query('UPDATE users SET wallet_balance=$1 WHERE id=$2', [newBalance, req.user.id]);

      const withdrawResult = await client.query(
        `INSERT INTO withdrawals (driver_id, amount, method, account_details, status)
         VALUES ($1,$2,'bank_transfer','{}','pending') RETURNING *`,
        [req.user.id, amountNaira]
      );
      const ref = 'WTH-' + uuidv4().split('-')[0].toUpperCase();
      await client.query(
        `INSERT INTO wallet_transactions (user_id,type,amount,balance_after,description,reference_code)
         VALUES ($1,'withdrawal',$2,$3,'Withdrawal request',$4)`,
        [req.user.id, amountNaira, newBalance, ref]
      );
      await client.query('COMMIT');

      io.to('admin_monitoring').emit('withdrawal:requested', {
        driverId: req.user.id, driverName: req.user.name,
        amount: amountNaira, withdrawalId: withdrawResult.rows[0].id,
      });

      res.json({ ok: true, net, fee, balance: newBalance });
    } catch (err) {
      await client.query('ROLLBACK');
      console.error('Withdrawal error:', err);
      res.status(500).json({ error: 'Withdrawal request failed.' });
    } finally { client.release(); }
  }
);

// ═══════════════════════════════════════════
//  ROUTES LISTING  (/api/routes/*)
// ═══════════════════════════════════════════

// Available trips for drivers to accept
app.get('/api/routes/available', authenticate, authorize('driver'), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT t.*, u.name AS member_name
       FROM trips t
       JOIN users u ON t.member_id = u.id
       WHERE t.status = 'pending'
       ORDER BY t.created_at ASC LIMIT 50`
    );
    res.json({ trips: result.rows });
  } catch (err) {
    console.error('Available routes error:', err);
    res.status(500).json({ error: 'Failed to fetch available trips.' });
  }
});

// Driver accepts a trip
app.post('/api/routes/:tripId/accept', authenticate, authorize('driver'), async (req, res) => {
  const { tripId } = req.params;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Check driver has no active trip
    const driverCheck = await client.query(
      `SELECT current_trip_id, is_available FROM driver_status WHERE driver_id=$1 FOR UPDATE`,
      [req.user.id]
    );
    if (driverCheck.rows[0]?.current_trip_id) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'You already have an active trip.' });
    }

    // Lock and claim the trip
    const tripResult = await client.query(
      `SELECT * FROM trips WHERE id=$1 AND status='pending' FOR UPDATE`,
      [tripId]
    );
    if (tripResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'Trip no longer available.' });
    }

    const trip = tripResult.rows[0];

    await client.query(
      `UPDATE trips SET driver_id=$1, status='accepted', accepted_at=NOW(), updated_at=NOW() WHERE id=$2`,
      [req.user.id, tripId]
    );
    await client.query(
      `INSERT INTO driver_status (driver_id, is_online, is_available, current_trip_id)
       VALUES ($1, true, false, $2)
       ON CONFLICT (driver_id) DO UPDATE SET is_available=false, current_trip_id=$2`,
      [req.user.id, tripId]
    );

    await client.query('COMMIT');

    // Notify passenger
    io.to(`user_${trip.member_id}`).emit('trip:accepted', {
      tripId, driverId: req.user.id, driverName: req.user.name,
    });
    io.to('admin_monitoring').emit('trip:accepted', {
      tripId, driverId: req.user.id, memberId: trip.member_id,
    });

    const updated = (await pool.query('SELECT * FROM trips WHERE id=$1', [tripId])).rows[0];
    res.json({ trip: updated });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Accept trip error:', err);
    res.status(500).json({ error: 'Failed to accept trip.' });
  } finally { client.release(); }
});

// Driver starts trip (after verifying passenger code)
app.post('/api/routes/:tripId/start', authenticate, authorize('driver'), async (req, res) => {
  const { tripId } = req.params;
  try {
    const result = await pool.query(
      `UPDATE trips SET status='ongoing', started_at=NOW(), updated_at=NOW()
       WHERE id=$1 AND driver_id=$2 AND status='accepted' RETURNING *`,
      [tripId, req.user.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Trip not found or cannot start.' });

    io.to(`user_${result.rows[0].member_id}`).emit('trip:started', { tripId });
    io.to('admin_monitoring').emit('trip:started', { tripId });
    res.json({ trip: result.rows[0] });
  } catch (err) {
    console.error('Start trip error:', err);
    res.status(500).json({ error: 'Failed to start trip.' });
  }
});

// Driver completes trip — fare deducted from member, 80% credited to driver
app.post('/api/routes/:tripId/complete', authenticate, authorize('driver'), async (req, res) => {
  const { tripId } = req.params;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const tripResult = await client.query(
      `SELECT * FROM trips WHERE id=$1 AND driver_id=$2 AND status='ongoing' FOR UPDATE`,
      [tripId, req.user.id]
    );
    if (tripResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Trip not found or cannot complete.' });
    }
    const trip = tripResult.rows[0];
    const fare = parseFloat(trip.fare);

    // Debit member wallet
    const memberWallet = await client.query(
      'SELECT wallet_balance FROM users WHERE id=$1 FOR UPDATE', [trip.member_id]
    );
    const memberBalance = parseFloat(memberWallet.rows[0].wallet_balance);
    if (memberBalance < fare) {
      await client.query('ROLLBACK');
      return res.status(402).json({ error: 'Passenger has insufficient balance.' });
    }
    const memberNewBalance = memberBalance - fare;
    await client.query('UPDATE users SET wallet_balance=$1 WHERE id=$2', [memberNewBalance, trip.member_id]);
    await client.query(
      `INSERT INTO wallet_transactions (user_id, trip_id, type, amount, balance_after, description)
       VALUES ($1,$2,'debit',$3,$4,'Trip fare')`,
      [trip.member_id, tripId, fare, memberNewBalance]
    );

    // Credit driver 80% of fare
    const driverEarning = Math.round(fare * 0.80 * 100) / 100;
    const driverWallet  = await client.query(
      'SELECT wallet_balance FROM users WHERE id=$1 FOR UPDATE', [req.user.id]
    );
    const driverNewBalance = parseFloat(driverWallet.rows[0].wallet_balance) + driverEarning;
    await client.query('UPDATE users SET wallet_balance=$1 WHERE id=$2', [driverNewBalance, req.user.id]);
    await client.query(
      `INSERT INTO wallet_transactions (user_id, trip_id, type, amount, balance_after, description)
       VALUES ($1,$2,'credit',$3,$4,'Trip earnings (80%)')`,
      [req.user.id, tripId, driverEarning, driverNewBalance]
    );

    // Mark trip complete
    await client.query(
      `UPDATE trips SET status='completed', completed_at=NOW(), updated_at=NOW() WHERE id=$1`,
      [tripId]
    );

    // Free driver
    await client.query(
      `UPDATE driver_status SET is_available=true, current_trip_id=NULL WHERE driver_id=$1`,
      [req.user.id]
    );

    await client.query('COMMIT');

    io.to(`user_${trip.member_id}`).emit('trip:completed', { tripId, fare });
    io.to('admin_monitoring').emit('trip:completed', { tripId, fare, driverEarning });

    res.json({ ok: true, fare, driverEarning, driverBalance: driverNewBalance });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Complete trip error:', err);
    res.status(500).json({ error: 'Failed to complete trip.' });
  } finally { client.release(); }
});

// ═══════════════════════════════════════════
//  VERIFICATION  (/api/verification/*)
// ═══════════════════════════════════════════

app.post('/api/verification/verify-code', authenticate, authorize('driver'), async (req, res) => {
  const { tripId, code } = req.body;
  try {
    const result = await pool.query(
      `SELECT * FROM trips WHERE id=$1 AND driver_id=$2 AND status='accepted'`,
      [tripId, req.user.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Trip not found.' });
    const trip = result.rows[0];
    if (trip.verification_code !== parseInt(code)) {
      return res.status(400).json({ error: 'Incorrect verification code.' });
    }
    res.json({ ok: true, verified: true });
  } catch (err) {
    console.error('Verify code error:', err);
    res.status(500).json({ error: 'Verification failed.' });
  }
});

// ═══════════════════════════════════════════
//  SAFETY  (/api/safety/*)
// ═══════════════════════════════════════════

app.post('/api/safety/sos', authenticate, async (req, res) => {
  const { lat, lng } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO sos_events (user_id, role, lat, lng, status)
       VALUES ($1,$2,$3,$4,'triggered') RETURNING *`,
      [req.user.id, req.user.role, lat ?? null, lng ?? null]
    );
    const sos = result.rows[0];
    io.to('admin_monitoring').emit('safety:sos', {
      sosId: sos.id, userId: req.user.id, userName: req.user.name,
      role: req.user.role, lat, lng, at: sos.created_at,
    });
    res.json({ ok: true, sosId: sos.id });
  } catch (err) {
    console.error('SOS error:', err);
    res.status(500).json({ error: 'SOS submission failed.' });
  }
});

app.patch('/api/safety/sos/:id/resolve', authenticate, authorize('admin'), async (req, res) => {
  try {
    await pool.query(
      `UPDATE sos_events SET status='resolved', resolved_at=NOW() WHERE id=$1`, [req.params.id]
    );
    io.to('admin_monitoring').emit('safety:sos_resolved', { sosId: req.params.id });
    res.json({ ok: true });
  } catch (err) {
    console.error('SOS resolve error:', err);
    res.status(500).json({ error: 'Failed to resolve SOS.' });
  }
});

// ═══════════════════════════════════════════
//  DRIVER STATUS  (/api/driver/status)
// ═══════════════════════════════════════════

app.get('/api/driver/status', authenticate, authorize('driver'), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT ds.*, t.pickup_address, t.dropoff_address, t.status AS trip_status
       FROM driver_status ds
       LEFT JOIN trips t ON ds.current_trip_id = t.id
       WHERE ds.driver_id = $1`,
      [req.user.id]
    );
    res.json({ status: result.rows[0] || { is_online: false, is_available: false } });
  } catch (err) {
    console.error('Driver status error:', err);
    res.status(500).json({ error: 'Failed to fetch status.' });
  }
});

app.patch('/api/driver/status', authenticate, authorize('driver'),
  [body('is_online').isBoolean()],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const { is_online } = req.body;
    try {
      await pool.query(
        `INSERT INTO driver_status (driver_id, is_online, is_available, last_online_at)
         VALUES ($1,$2,$2,NOW())
         ON CONFLICT (driver_id) DO UPDATE
         SET is_online=$2, is_available=$2, last_online_at=NOW(), updated_at=NOW()`,
        [req.user.id, is_online]
      );
      if (is_online) {
        io.to('admin_monitoring').emit('driver:online', { driverId: req.user.id, name: req.user.name });
      } else {
        io.to('admin_monitoring').emit('driver:offline', { driverId: req.user.id });
      }
      res.json({ ok: true, is_online });
    } catch (err) {
      console.error('Set status error:', err);
      res.status(500).json({ error: 'Failed to update status.' });
    }
  }
);

// Online drivers list for admin live map
app.get('/api/drivers/online', authenticate, authorize('admin'), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.id, u.name, u.phone, ds.is_available, ds.current_trip_id,
              ll.lat, ll.lng, ll.heading, ll.speed, ll.updated_at AS location_updated
       FROM users u
       JOIN driver_status ds ON u.id = ds.driver_id
       LEFT JOIN live_locations ll ON u.id = ll.driver_id
       WHERE ds.is_online=true AND u.role='driver' AND u.is_active=true`
    );
    res.json({ drivers: result.rows });
  } catch (err) {
    console.error('Online drivers error:', err);
    res.status(500).json({ error: 'Failed to fetch drivers.' });
  }
});

// ═══════════════════════════════════════════
//  SOCKET.IO REAL-TIME GATEWAY
// ═══════════════════════════════════════════

const io = new Server(server, {
  cors: {
    origin: ALLOWED_ORIGINS,
    methods: ['GET', 'POST'],
    credentials: true,
  },
  pingTimeout: 60000,
  pingInterval: 25000,
});

// Socket auth middleware
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    if (!token) return next(new Error('Authentication error: No token'));

    const decoded = jwt.verify(token, JWT_SECRET);
    const result  = await pool.query(
      'SELECT id, role, name, is_active FROM users WHERE id = $1', [decoded.id]
    );
    if (result.rows.length === 0) return next(new Error('User not found'));
    if (!result.rows[0].is_active)  return next(new Error('Account deactivated'));

    socket.userId   = result.rows[0].id;
    socket.userRole = result.rows[0].role;
    socket.userName = result.rows[0].name;
    next();
  } catch (err) {
    next(new Error('Authentication error: ' + err.message));
  }
});

io.on('connection', (socket) => {
  console.log(`🔌 ${socket.userName} (${socket.userRole}) connected`);

  socket.join(`user_${socket.userId}`);
  socket.join(`role_${socket.userRole}`);
  if (socket.userRole === 'driver') socket.join('drivers_online');
  if (socket.userRole === 'admin')  socket.join('admin_monitoring');

  // ── Driver GPS location ──────────────────────────────────────────
  socket.on('driver:location_update', async (data) => {
    if (socket.userRole !== 'driver') return;
    try {
      const { lat, lng, heading, speed } = data;
      await pool.query(
        `INSERT INTO live_locations (driver_id, lat, lng, heading, speed, updated_at)
         VALUES ($1,$2,$3,$4,$5,NOW())
         ON CONFLICT (driver_id) DO UPDATE SET lat=$2,lng=$3,heading=$4,speed=$5,updated_at=NOW()`,
        [socket.userId, lat, lng, heading ?? null, speed ?? null]
      );

      const activeTrip = await pool.query(
        `SELECT id, member_id FROM trips WHERE driver_id=$1 AND status IN ('accepted','ongoing')`,
        [socket.userId]
      );
      if (activeTrip.rows.length > 0) {
        const { id: tripId, member_id } = activeTrip.rows[0];
        await pool.query(
          `INSERT INTO route_history (trip_id, driver_id, lat, lng, heading, speed)
           VALUES ($1,$2,$3,$4,$5,$6)`,
          [tripId, socket.userId, lat, lng, heading ?? null, speed ?? null]
        );
        io.to(`user_${member_id}`).emit('trip:driver_location', {
          tripId, driverId: socket.userId, lat, lng, heading, speed,
          timestamp: new Date().toISOString(),
        });
      }

      io.to('admin_monitoring').emit('driver:location', {
        driverId: socket.userId, driverName: socket.userName,
        lat, lng, heading, speed, timestamp: new Date().toISOString(),
      });
    } catch (err) {
      console.error('Location update error:', err);
    }
  });

  // ── In-trip chat ─────────────────────────────────────────────────
  socket.on('trip:message', async (data) => {
    try {
      const { tripId, message } = data;
      const tripCheck = await pool.query(
        `SELECT member_id, driver_id FROM trips
         WHERE id=$1 AND (member_id=$2 OR driver_id=$2)`,
        [tripId, socket.userId]
      );
      if (tripCheck.rows.length === 0) return socket.emit('error', { message: 'Not authorized.' });

      const msgResult = await pool.query(
        `INSERT INTO trip_messages (trip_id, sender_id, message) VALUES ($1,$2,$3) RETURNING *`,
        [tripId, socket.userId, message]
      );
      const msg = {
        id: msgResult.rows[0].id, tripId,
        senderId: socket.userId, senderName: socket.userName,
        message, createdAt: msgResult.rows[0].created_at,
      };
      const { member_id, driver_id } = tripCheck.rows[0];
      io.to(`user_${member_id}`).emit('trip:message', msg);
      io.to(`user_${driver_id}`).emit('trip:message', msg);
      io.to('admin_monitoring').emit('trip:message', { ...msg, _monitored: true });
    } catch (err) {
      console.error('Chat error:', err);
      socket.emit('error', { message: 'Failed to send message.' });
    }
  });

  socket.on('disconnect', () => {
    console.log(`🔌 ${socket.userName} disconnected`);
  });
});


// ═══════════════════════════════════════════
//  PIN RESET (OTP)  — driver/member self-service
// ═══════════════════════════════════════════
app.post('/api/auth/request-reset', authLimiter, async (req, res) => {
  const phone = (req.body.phone || '').replace(/\s/g, '');
  if (!phone) return res.status(400).json({ error: 'Phone required.' });
  try {
    const r = await pool.query('SELECT id FROM users WHERE phone=$1 AND is_active=true', [phone]);
    // Always respond ok to avoid user enumeration.
    if (!r.rows[0]) return res.json({ ok: true });
    const code = String(Math.floor(100000 + Math.random() * 900000));
    await pool.query(
      `INSERT INTO pin_resets (user_id, code, expires_at) VALUES ($1,$2, NOW() + INTERVAL '15 minutes')`,
      [r.rows[0].id, code]
    );
    // In production, send via SMS/email provider. In test mode, return the code.
    const devMode = NODE_ENV !== 'production';
    console.log(`🔑 PIN reset code for ${phone}: ${code}`);
    res.json({ ok: true, ...(devMode ? { devCode: code } : {}) });
  } catch (err) {
    console.error('request-reset error:', err);
    res.status(500).json({ error: 'Could not start reset.' });
  }
});

app.post('/api/auth/confirm-reset', authLimiter, async (req, res) => {
  const phone = (req.body.phone || '').replace(/\s/g, '');
  const { code, newPin } = req.body;
  if (!phone || !code || !/^\d{4,6}$/.test(newPin || '')) {
    return res.status(400).json({ error: 'Phone, code and a valid new PIN are required.' });
  }
  try {
    const u = await pool.query('SELECT id FROM users WHERE phone=$1', [phone]);
    if (!u.rows[0]) return res.status(400).json({ error: 'Invalid reset request.' });
    const userId = u.rows[0].id;
    const reset = await pool.query(
      `SELECT id FROM pin_resets
       WHERE user_id=$1 AND code=$2 AND used=false AND expires_at > NOW()
       ORDER BY created_at DESC LIMIT 1`,
      [userId, String(code)]
    );
    if (!reset.rows[0]) return res.status(400).json({ error: 'Invalid or expired code.' });

    const hash = await bcrypt.hash(newPin, 12);
    await pool.query('UPDATE users SET password_hash=$1, updated_at=NOW() WHERE id=$2', [hash, userId]);
    await pool.query('UPDATE pin_resets SET used=true WHERE id=$1', [reset.rows[0].id]);
    res.json({ ok: true });
  } catch (err) {
    console.error('confirm-reset error:', err);
    res.status(500).json({ error: 'Reset failed.' });
  }
});

// ═══════════════════════════════════════════
//  PROFILE — extend PATCH to accept email + photo
// ═══════════════════════════════════════════
app.patch('/api/profile/full', authenticate,
  [body('name').optional().trim().notEmpty()],
  async (req, res) => {
    const { name, email, photoUrl } = req.body;
    try {
      const r = await pool.query(
        `UPDATE users SET
           name      = COALESCE($1, name),
           email     = COALESCE($2, email),
           photo_url = COALESCE($3, photo_url),
           updated_at = NOW()
         WHERE id=$4 RETURNING *`,
        [name || null, email || null, photoUrl || null, req.user.id]
      );
      res.json({ user: publicUser(r.rows[0]) });
    } catch (err) {
      console.error('profile update error:', err);
      res.status(500).json({ error: 'Failed to update profile.' });
    }
  }
);

// ═══════════════════════════════════════════
//  ROUTES — list, book, request
// ═══════════════════════════════════════════
const DEMO_ROUTES = [
  { id: 'ELZ-01', code: 'ELZ-01', from: 'Eliozu Junction', to: 'Trans Amadi', departure: '6:35 AM', seatsTotal: 6, seatsTaken: 4, fare: 0, rideType: 'shared', days: ['Mon','Tue','Wed','Thu','Fri'] },
  { id: 'RMK-02', code: 'RMK-02', from: 'Rumuokoro', to: 'Aba Road', departure: '7:10 AM', seatsTotal: 6, seatsTaken: 2, fare: 1200, rideType: 'fleet', days: ['Mon','Wed','Fri'] },
  { id: 'CHB-03', code: 'CHB-03', from: 'Choba', to: 'GRA Phase 2', departure: '8:00 AM', seatsTotal: 14, seatsTaken: 5, fare: 1500, rideType: 'corporate', days: ['Mon','Tue','Wed','Thu','Fri'] },
];

app.get('/api/routes', authenticate, async (req, res) => {
  const q = (req.query.q || '').toString().toLowerCase();
  const filtered = q
    ? DEMO_ROUTES.filter(r =>
        r.code.toLowerCase().includes(q) || r.from.toLowerCase().includes(q) || r.to.toLowerCase().includes(q))
    : DEMO_ROUTES;
  res.json({ routes: filtered });
});

app.post('/api/routes/book', authenticate, authorize('member'), async (req, res) => {
  const { from, to, rideType = 'shared', passengers = 1 } = req.body;
  if (!from || !to) return res.status(400).json({ error: 'Pickup and drop-off required.' });
  const verificationCode = String(Math.floor(100 + Math.random() * 900));
  const trip = {
    id: uuidv4(), routeCode: 'REQ-' + Date.now().toString().slice(-4),
    from, to, status: 'matched', driverName: 'Emeka Ikenna',
    vehicle: 'Silver Corolla', plate: 'RV 248 KJA',
    verificationCode, memberId: req.user.id, driverId: 'demo-driver',
    rideType, passengers,
  };
  io.to('admin_monitoring').emit('trip:created', { trip });
  res.status(201).json({ trip });
});

app.post('/api/routes/request', authenticate, async (req, res) => {
  const { from, to, time, days = [], seats = 1, notes } = req.body;
  if (!from || !to) return res.status(400).json({ error: 'Origin and destination required.' });
  try {
    const r = await pool.query(
      `INSERT INTO route_requests (requested_by, requester_role, origin, destination, preferred_time, days, seats, notes)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
      [req.user.id, req.user.role, from, to, time || null, days, seats, notes || null]
    );
    io.to('admin_monitoring').emit('route:requested', { id: r.rows[0].id, from, to, by: req.user.role });
    res.status(201).json({ ok: true, id: r.rows[0].id });
  } catch (err) {
    console.error('route request error:', err);
    res.status(500).json({ error: 'Could not submit route request.' });
  }
});

// ═══════════════════════════════════════════
//  VERIFICATION — generic verify (alias used by web app)
// ═══════════════════════════════════════════
app.post('/api/verification/verify', authenticate, async (req, res) => {
  const { tripId, code } = req.body;
  // Demo trips (id starting with REQ- or 'demo') verify against any 3-digit code echo.
  if (!tripId || tripId === 'demo' || String(tripId).startsWith('REQ-')) {
    return res.json({ ok: true, trip: { id: tripId, status: 'boarded' } });
  }
  try {
    const r = await pool.query(`SELECT * FROM trips WHERE id=$1`, [tripId]);
    const trip = r.rows[0];
    if (!trip) return res.status(404).json({ error: 'Trip not found.' });
    if (String(trip.verification_code) !== String(code)) {
      return res.status(400).json({ error: 'Incorrect verification code.' });
    }
    res.json({ ok: true, trip });
  } catch (err) {
    console.error('verify error:', err);
    res.status(500).json({ error: 'Verification failed.' });
  }
});

// ═══════════════════════════════════════════
//  DRIVER DOCUMENTS
// ═══════════════════════════════════════════
app.get('/api/driver/documents', authenticate, authorize('driver'), async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT document_type AS type, status, file_name AS "fileName",
              notes AS "rejectionReason", updated_at AS "uploadedAt"
       FROM driver_documents WHERE driver_id=$1`,
      [req.user.id]
    );
    res.json({ documents: r.rows });
  } catch (err) {
    console.error('get documents error:', err);
    res.status(500).json({ error: 'Failed to load documents.' });
  }
});

app.post('/api/driver/documents', authenticate, authorize('driver'),
  [body('type').notEmpty(), body('dataUrl').notEmpty()],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const { type, dataUrl, fileName } = req.body;
    try {
      await pool.query(
        `INSERT INTO driver_documents (driver_id, document_type, document_url, file_name, status)
         VALUES ($1,$2,$3,$4,'pending')
         ON CONFLICT (driver_id, document_type)
         DO UPDATE SET document_url=$3, file_name=$4, status='pending', notes=NULL, updated_at=NOW()`,
        [req.user.id, type, dataUrl, fileName || null]
      );
      // If this is the passport photo, also set it as the user's profile photo.
      if (type === 'passport_photo') {
        await pool.query('UPDATE users SET photo_url=$1 WHERE id=$2', [dataUrl, req.user.id]);
      }
      res.json({ ok: true, document: { type, status: 'pending', fileName } });
    } catch (err) {
      console.error('upload document error:', err);
      res.status(500).json({ error: 'Upload failed.' });
    }
  }
);

app.post('/api/driver/documents/submit', authenticate, authorize('driver'), async (req, res) => {
  try {
    await pool.query(`UPDATE users SET verification_status='pending', updated_at=NOW() WHERE id=$1`, [req.user.id]);
    io.to('admin_monitoring').emit('driver:verification_submitted', { driverId: req.user.id, name: req.user.name });
    res.json({ ok: true, status: 'pending' });
  } catch (err) {
    console.error('submit verification error:', err);
    res.status(500).json({ error: 'Submit failed.' });
  }
});

// ═══════════════════════════════════════════
//  DRIVER VEHICLE
// ═══════════════════════════════════════════
app.get('/api/driver/vehicle', authenticate, authorize('driver'), async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT model, plate_number AS plate, color, capacity,
              seat_preference AS "seatPreference", photo_url AS "photoUrl"
       FROM driver_vehicles WHERE driver_id=$1 LIMIT 1`,
      [req.user.id]
    );
    res.json({ vehicle: r.rows[0] || null });
  } catch (err) {
    console.error('get vehicle error:', err);
    res.status(500).json({ error: 'Failed to load vehicle.' });
  }
});

app.post('/api/driver/vehicle', authenticate, authorize('driver'),
  [
    body('model').trim().notEmpty(),
    body('plate').trim().notEmpty(),
    body('capacity').isInt({ min: 1, max: 30 }),
    body('seatPreference').isInt({ min: 1, max: 30 }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const { model, plate, color, capacity, seatPreference, photoUrl } = req.body;
    if (Number(seatPreference) > Number(capacity)) {
      return res.status(400).json({ error: 'Seat preference cannot exceed vehicle capacity.' });
    }
    try {
      const existing = await pool.query('SELECT id FROM driver_vehicles WHERE driver_id=$1 LIMIT 1', [req.user.id]);
      if (existing.rows[0]) {
        await pool.query(
          `UPDATE driver_vehicles SET model=$1, plate_number=$2, color=$3, capacity=$4,
             seat_preference=$5, photo_url=$6, updated_at=NOW() WHERE driver_id=$7`,
          [model, plate, color || '', capacity, seatPreference, photoUrl || null, req.user.id]
        );
      } else {
        await pool.query(
          `INSERT INTO driver_vehicles (driver_id, plate_number, model, color, capacity, seat_preference, photo_url)
           VALUES ($1,$2,$3,$4,$5,$6,$7)`,
          [req.user.id, plate, model, color || '', capacity, seatPreference, photoUrl || null]
        );
      }
      res.json({ ok: true, vehicle: { model, plate, color, capacity, seatPreference, photoUrl } });
    } catch (err) {
      console.error('save vehicle error:', err);
      res.status(500).json({ error: 'Failed to save vehicle.' });
    }
  }
);

// ═══════════════════════════════════════════
//  DRIVER AVAILABILITY (online + seat preference)
// ═══════════════════════════════════════════
app.post('/api/driver/availability', authenticate, authorize('driver'),
  [body('available').isBoolean()],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const { available, seatPreference } = req.body;
    try {
      await pool.query(
        `INSERT INTO driver_status (driver_id, is_online, is_available, last_online_at)
         VALUES ($1,$2,$2,NOW())
         ON CONFLICT (driver_id) DO UPDATE
         SET is_online=$2, is_available=$2, last_online_at=NOW(), updated_at=NOW()`,
        [req.user.id, available]
      );
      if (seatPreference != null) {
        await pool.query(
          `UPDATE driver_vehicles SET seat_preference=$1, updated_at=NOW() WHERE driver_id=$2`,
          [seatPreference, req.user.id]
        );
      }
      io.to('admin_monitoring').emit(available ? 'driver:online' : 'driver:offline',
        { driverId: req.user.id, name: req.user.name });
      res.json({ ok: true });
    } catch (err) {
      console.error('availability error:', err);
      res.status(500).json({ error: 'Failed to update availability.' });
    }
  }
);


// Export io for use in route modules that need it
app.set('io', io);

// ═══════════════════════════════════════════
//  ERROR HANDLERS
// ═══════════════════════════════════════════
app.use((err, req, res, _next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error.' });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found.' });
});

// ═══════════════════════════════════════════
//  START
// ═══════════════════════════════════════════
server.listen(PORT, () => {
  console.log(`\n🚀  Komyut API  →  http://localhost:${PORT}`);
  console.log(`📡  WebSocket   →  ws://localhost:${PORT}`);
  console.log(`🔒  Environment →  ${NODE_ENV}`);
  console.log(`🌐  CORS origins→  ${ALLOWED_ORIGINS.join(', ')}\n`);
});

module.exports = { app, server, io };
