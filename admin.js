/**
 * routes/admin.js
 * All admin-only endpoints:
 *   GET    /api/admin/dashboard/overview
 *   GET    /api/admin/users
 *   GET    /api/admin/users/:userId
 *   PATCH  /api/admin/users/:userId/status
 *   GET    /api/admin/documents/pending
 *   POST   /api/admin/documents/:documentId/review
 *   GET    /api/admin/drivers/:driverId/documents
 *   GET    /api/admin/drivers/:driverId/verification-status
 *   GET    /api/admin/withdrawals
 *   POST   /api/admin/withdrawals/:withdrawalId/process
 *   GET    /api/admin/reports/weekly
 *   GET    /api/admin/reports/top-drivers
 *   GET    /api/admin/reports/trip-status
 *   GET    /api/admin/reports/monthly
 *   GET    /api/admin/trips/all
 *   POST   /api/admin/trips/:tripId/force-cancel
 *   GET    /api/admin/settings
 *   PUT    /api/admin/settings/:key
 *   GET    /api/admin/surge-pricing
 *   POST   /api/admin/surge-pricing
 *   PATCH  /api/admin/surge-pricing/:ruleId
 *   DELETE /api/admin/surge-pricing/:ruleId
 */

const express = require('express');
const { body, query, validationResult } = require('express-validator');
const pool = require('../db');
const { authenticate, authorize } = require('../middleware/auth');

const router = express.Router();

// All routes require an authenticated admin account
router.use(authenticate, authorize('admin'));

// ── Role-Based Access Control ─────────────────────────────────────
// Staff roles map to a fixed permission set. super_admin can do everything.
const STAFF_PERMISSIONS = {
  super_admin: { manageUsers: true,  approveDrivers: true,  manageFinance: true,  monitorChat: true,  resetPlatform: true,  manageStaff: true  },
  operations:  { manageUsers: true,  approveDrivers: true,  manageFinance: false, monitorChat: true,  resetPlatform: false, manageStaff: false },
  support:     { manageUsers: false, approveDrivers: false, manageFinance: false, monitorChat: true,  resetPlatform: false, manageStaff: false },
  finance:     { manageUsers: false, approveDrivers: false, manageFinance: true,  monitorChat: false, resetPlatform: false, manageStaff: false },
};

// Load the admin's staff_role onto req for permission checks.
router.use(async (req, res, next) => {
  try {
    const r = await pool.query('SELECT staff_role FROM users WHERE id = $1', [req.user.id]);
    // Default older admins (no staff_role set) to super_admin so nothing breaks.
    req.staffRole = r.rows[0]?.staff_role || 'super_admin';
    req.perms = STAFF_PERMISSIONS[req.staffRole] || STAFF_PERMISSIONS.super_admin;
    next();
  } catch (err) {
    console.error('RBAC load error:', err);
    res.status(500).json({ error: 'Could not verify permissions.' });
  }
});

// Guard factory: require a specific permission.
function requirePerm(perm) {
  return (req, res, next) => {
    if (!req.perms?.[perm]) {
      return res.status(403).json({ error: `Your role (${req.staffRole}) cannot perform this action.` });
    }
    next();
  };
}

// Lightweight audit logger (best-effort; never blocks the response).
async function audit(req, action, target, detail) {
  try {
    await pool.query(
      `INSERT INTO audit_log (actor_id, actor_name, action, target, detail) VALUES ($1,$2,$3,$4,$5)`,
      [req.user.id, req.user.name, action, target || null, detail || null]
    );
  } catch { /* audit table may not exist on older DBs — ignore */ }
}

// Expose current admin's permissions to the panel.
router.get('/me/permissions', (req, res) => {
  res.json({ staffRole: req.staffRole, permissions: req.perms });
});

// ========================
// DASHBOARD OVERVIEW
// ========================

router.get('/dashboard/overview', async (req, res) => {
    try {
        const [users, todayTrips, todayRevenue, pendingWithdrawals, pendingDocuments, activeDrivers] =
            await Promise.all([
                pool.query(`
                    SELECT
                        COUNT(*)::int                                       AS total_users,
                        COUNT(*) FILTER (WHERE role = 'member')::int       AS members,
                        COUNT(*) FILTER (WHERE role = 'driver')::int       AS drivers,
                        COUNT(*) FILTER (WHERE role = 'admin')::int        AS admins
                    FROM users WHERE is_active = true`),

                pool.query(`
                    SELECT
                        COUNT(*)::int                                             AS count,
                        COUNT(*) FILTER (WHERE status = 'completed')::int        AS completed
                    FROM trips
                    WHERE DATE(created_at) = CURRENT_DATE`),

                pool.query(`
                    SELECT
                        COALESCE(SUM(fare), 0)        AS revenue,
                        COALESCE(SUM(fare * 0.20), 0) AS commission
                    FROM trips
                    WHERE status = 'completed'
                      AND DATE(completed_at) = CURRENT_DATE`),

                pool.query(`
                    SELECT COUNT(*)::int AS count
                    FROM withdrawals WHERE status = 'pending'`),

                pool.query(`
                    SELECT COUNT(*)::int AS count
                    FROM driver_documents WHERE status = 'pending'`),

                pool.query(`
                    SELECT COUNT(*)::int AS count
                    FROM driver_status WHERE is_online = true`)
            ]);

        res.json({
            users:               users.rows[0],
            today_trips:         todayTrips.rows[0],
            today_revenue:       {
                revenue:    parseFloat(todayRevenue.rows[0].revenue),
                commission: parseFloat(todayRevenue.rows[0].commission)
            },
            pending_withdrawals: pendingWithdrawals.rows[0].count,
            pending_documents:   pendingDocuments.rows[0].count,
            active_drivers:      activeDrivers.rows[0].count
        });
    } catch (err) {
        console.error('Dashboard overview error:', err);
        res.status(500).json({ error: 'Failed to fetch overview.' });
    }
});

// ========================
// USER MANAGEMENT
// ========================

router.get('/users', [
    query('role').optional().isIn(['member', 'driver', 'admin']),
    query('search').optional().trim(),
    query('is_active').optional().isBoolean(),
    query('limit').optional().isInt({ min: 1, max: 200 }),
    query('offset').optional().isInt({ min: 0 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { role, search, is_active, limit = 50, offset = 0 } = req.query;
    const params = [];
    const conditions = [];

    if (role) {
        params.push(role);
        conditions.push(`u.role = $${params.length}`);
    }

    if (search) {
        params.push(`%${search}%`);
        conditions.push(`(u.name ILIKE $${params.length} OR u.phone ILIKE $${params.length})`);
    }

    if (is_active !== undefined) {
        params.push(is_active === 'true');
        conditions.push(`u.is_active = $${params.length}`);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    params.push(parseInt(limit), parseInt(offset));

    try {
        const result = await pool.query(
            `SELECT u.id, u.role, u.name, u.phone, u.email, u.user_type, u.company_name,
                    u.wallet_balance, u.is_active, u.is_blocked, u.is_restricted,
                    u.verification_status, u.rating, u.created_at,
                    ds.is_online, ds.is_available
             FROM users u
             LEFT JOIN driver_status ds ON u.id = ds.driver_id
             ${whereClause}
             ORDER BY u.created_at DESC
             LIMIT $${params.length - 1} OFFSET $${params.length}`,
            params
        );
        res.json({ users: result.rows });
    } catch (err) {
        console.error('List users error:', err);
        res.status(500).json({ error: 'Failed to fetch users.' });
    }
});

router.get('/users/:userId', async (req, res) => {
    const { userId } = req.params;

    try {
        const userResult = await pool.query(
            `SELECT u.id, u.role, u.name, u.phone, u.email, u.photo_url,
                    u.user_type, u.company_name, u.wallet_balance,
                    u.is_active, u.is_blocked, u.is_restricted, u.restriction_note,
                    u.verification_status, u.rating, u.staff_role, u.created_at,
                    ds.is_online, ds.is_available, ds.current_trip_id
             FROM users u
             LEFT JOIN driver_status ds ON u.id = ds.driver_id
             WHERE u.id = $1`,
            [userId]
        );

        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found.' });
        }

        const user = userResult.rows[0];

        const statsResult = await pool.query(
            `SELECT
                COUNT(*) FILTER (WHERE status = 'completed')::int AS completed_trips,
                COUNT(*) FILTER (WHERE status = 'cancelled')::int  AS cancelled_trips,
                COALESCE(SUM(fare) FILTER (WHERE status = 'completed'), 0) AS total_spent
             FROM trips
             WHERE member_id = $1 OR driver_id = $1`,
            [userId]
        );

        // For drivers, also return their documents + vehicle so admin can review.
        let documents = [];
        let vehicle = null;
        if (user.role === 'driver') {
            documents = (await pool.query(
                `SELECT document_type, status, file_name, document_url, notes, created_at, updated_at
                 FROM driver_documents WHERE driver_id = $1`,
                [userId]
            )).rows;
            vehicle = (await pool.query(
                `SELECT model, plate_number, color, capacity, seat_preference, photo_url
                 FROM driver_vehicles WHERE driver_id = $1 LIMIT 1`,
                [userId]
            )).rows[0] || null;
        }

        res.json({ user, stats: statsResult.rows[0], documents, vehicle });
    } catch (err) {
        console.error('Get user error:', err);
        res.status(500).json({ error: 'Failed to fetch user.' });
    }
});

// Block / unblock a user (manageUsers permission)
router.patch('/users/:userId/block', requirePerm('manageUsers'),
  [body('blocked').isBoolean()],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const { userId } = req.params;
    const { blocked, reason } = req.body;
    if (userId === req.user.id) return res.status(400).json({ error: 'You cannot block your own account.' });
    try {
        const r = await pool.query(
            `UPDATE users SET is_blocked=$1, restriction_note=COALESCE($2, restriction_note), updated_at=NOW()
             WHERE id=$3 RETURNING id, name, is_blocked`,
            [blocked, reason || null, userId]
        );
        if (!r.rows[0]) return res.status(404).json({ error: 'User not found.' });
        await audit(req, blocked ? 'block_user' : 'unblock_user', userId, reason);
        res.json({ user: r.rows[0] });
    } catch (err) {
        console.error('Block user error:', err);
        res.status(500).json({ error: 'Failed to update user.' });
    }
});

// Restrict / unrestrict a user (manageUsers permission)
router.patch('/users/:userId/restrict', requirePerm('manageUsers'),
  [body('restricted').isBoolean()],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const { userId } = req.params;
    const { restricted, note } = req.body;
    try {
        const r = await pool.query(
            `UPDATE users SET is_restricted=$1, restriction_note=$2, updated_at=NOW()
             WHERE id=$3 RETURNING id, name, is_restricted, restriction_note`,
            [restricted, note || null, userId]
        );
        if (!r.rows[0]) return res.status(404).json({ error: 'User not found.' });
        await audit(req, restricted ? 'restrict_user' : 'unrestrict_user', userId, note);
        res.json({ user: r.rows[0] });
    } catch (err) {
        console.error('Restrict user error:', err);
        res.status(500).json({ error: 'Failed to update user.' });
    }
});

router.patch('/users/:userId/status', [
    body('is_active').isBoolean().withMessage('is_active must be boolean')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { userId } = req.params;
    const { is_active } = req.body;

    // Prevent admin from deactivating themselves
    if (userId === req.user.id && !is_active) {
        return res.status(400).json({ error: 'Cannot deactivate your own account.' });
    }

    try {
        const result = await pool.query(
            `UPDATE users SET is_active = $1, updated_at = NOW()
             WHERE id = $2
             RETURNING id, name, role, is_active`,
            [is_active, userId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found.' });
        }

        res.json({ user: result.rows[0] });
    } catch (err) {
        console.error('Update status error:', err);
        res.status(500).json({ error: 'Failed to update status.' });
    }
});

// ========================
// DRIVER DOCUMENT VERIFICATION
// ========================

router.get('/documents/pending', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT dd.*, u.name AS driver_name, u.phone AS driver_phone
             FROM driver_documents dd
             JOIN users u ON dd.driver_id = u.id
             WHERE dd.status = 'pending'
             ORDER BY dd.created_at ASC`
        );
        res.json({ documents: result.rows });
    } catch (err) {
        console.error('Pending documents error:', err);
        res.status(500).json({ error: 'Failed to fetch pending documents.' });
    }
});

router.post('/documents/:documentId/review', [
    body('status').isIn(['approved', 'rejected']).withMessage("status must be 'approved' or 'rejected'"),
    body('notes').optional().trim()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { documentId } = req.params;
    const { status, notes } = req.body;

    try {
        const result = await pool.query(
            `UPDATE driver_documents
             SET status      = $1,
                 notes       = $2,
                 reviewer_id = $3,
                 reviewed_at = NOW(),
                 updated_at  = NOW()
             WHERE id = $4
             RETURNING *`,
            [status, notes || null, req.user.id, documentId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Document not found.' });
        }

        res.json({ document: result.rows[0] });
    } catch (err) {
        console.error('Review document error:', err);
        res.status(500).json({ error: 'Failed to review document.' });
    }
});

router.get('/drivers/:driverId/documents', async (req, res) => {
    const { driverId } = req.params;

    try {
        const result = await pool.query(
            `SELECT * FROM driver_documents
             WHERE driver_id = $1
             ORDER BY document_type`,
            [driverId]
        );
        res.json({ documents: result.rows });
    } catch (err) {
        console.error('Driver documents error:', err);
        res.status(500).json({ error: 'Failed to fetch documents.' });
    }
});

router.get('/drivers/:driverId/verification-status', async (req, res) => {
    const { driverId } = req.params;
    const REQUIRED_DOCS = ['license', 'or_cr', 'nbi_clearance'];

    try {
        const result = await pool.query(
            `SELECT document_type, status
             FROM driver_documents
             WHERE driver_id = $1`,
            [driverId]
        );

        const docMap = {};
        result.rows.forEach(r => { docMap[r.document_type] = r.status; });

        const isFullyVerified = REQUIRED_DOCS.every(type => docMap[type] === 'approved');
        const canDrive = isFullyVerified;

        const documents = {};
        REQUIRED_DOCS.forEach(type => {
            documents[type] = docMap[type] || 'not_uploaded';
        });

        res.json({ is_fully_verified: isFullyVerified, can_drive: canDrive, documents });
    } catch (err) {
        console.error('Verification status error:', err);
        res.status(500).json({ error: 'Failed to fetch verification status.' });
    }
});

// ========================
// WITHDRAWAL MANAGEMENT
// ========================

router.get('/withdrawals', [
    query('status').optional().isIn(['pending', 'completed', 'rejected'])
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { status } = req.query;
    const params = [];
    let whereClause = '';

    if (status) {
        params.push(status);
        whereClause = `WHERE w.status = $1`;
    }

    try {
        const result = await pool.query(
            `SELECT w.*, u.name AS driver_name, u.phone AS driver_phone
             FROM withdrawals w
             JOIN users u ON w.driver_id = u.id
             ${whereClause}
             ORDER BY w.created_at DESC`,
            params
        );
        res.json({ withdrawals: result.rows });
    } catch (err) {
        console.error('All withdrawals error:', err);
        res.status(500).json({ error: 'Failed to fetch withdrawals.' });
    }
});

router.post('/withdrawals/:withdrawalId/process', [
    body('status').isIn(['completed', 'rejected']).withMessage("status must be 'completed' or 'rejected'"),
    body('notes').optional().trim()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { withdrawalId } = req.params;
    const { status, notes } = req.body;
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        const wResult = await client.query(
            `SELECT * FROM withdrawals WHERE id = $1 AND status = 'pending' FOR UPDATE`,
            [withdrawalId]
        );

        if (wResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Withdrawal not found or already processed.' });
        }

        const withdrawal = wResult.rows[0];

        // If rejected, refund the driver's wallet
        if (status === 'rejected') {
            const walletResult = await client.query(
                'SELECT wallet_balance FROM users WHERE id = $1 FOR UPDATE',
                [withdrawal.driver_id]
            );

            const newBalance = parseFloat(walletResult.rows[0].wallet_balance) + parseFloat(withdrawal.amount);

            await client.query(
                'UPDATE users SET wallet_balance = $1 WHERE id = $2',
                [newBalance, withdrawal.driver_id]
            );

            await client.query(
                `INSERT INTO wallet_transactions
                    (user_id, type, amount, balance_after, description)
                 VALUES ($1, 'credit', $2, $3, $4)`,
                [withdrawal.driver_id, withdrawal.amount, newBalance,
                 `Refund: withdrawal ${withdrawalId} rejected`]
            );
        }

        const updated = await client.query(
            `UPDATE withdrawals
             SET status      = $1,
                 notes       = $2,
                 processed_by = $3,
                 processed_at = NOW(),
                 updated_at  = NOW()
             WHERE id = $4
             RETURNING *`,
            [status, notes || null, req.user.id, withdrawalId]
        );

        await client.query('COMMIT');
        res.json({ withdrawal: updated.rows[0] });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Process withdrawal error:', err);
        res.status(500).json({ error: 'Failed to process withdrawal.' });
    } finally {
        client.release();
    }
});

// ========================
// ANALYTICS & REPORTS
// ========================

router.get('/reports/weekly', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT
                DATE(completed_at)                AS date,
                COUNT(*)::int                      AS trips,
                COALESCE(SUM(fare), 0)             AS revenue,
                COALESCE(SUM(fare * 0.20), 0)     AS commission
             FROM trips
             WHERE status = 'completed'
               AND completed_at >= NOW() - INTERVAL '7 days'
             GROUP BY DATE(completed_at)
             ORDER BY date ASC`
        );

        res.json({
            daily: result.rows.map(r => ({
                date:       r.date,
                trips:      r.trips,
                revenue:    parseFloat(r.revenue),
                commission: parseFloat(r.commission)
            }))
        });
    } catch (err) {
        console.error('Weekly report error:', err);
        res.status(500).json({ error: 'Failed to fetch weekly report.' });
    }
});

router.get('/reports/top-drivers', [
    query('limit').optional().isInt({ min: 1, max: 100 })
], async (req, res) => {
    const limit = parseInt(req.query.limit) || 10;

    try {
        const result = await pool.query(
            `SELECT
                u.id, u.name, u.phone,
                COUNT(t.id)::int                           AS completed_trips,
                COALESCE(SUM(t.fare * 0.80), 0)           AS total_earnings,
                COALESCE(AVG(dr.rating), 0)               AS avg_rating
             FROM users u
             JOIN trips t ON u.id = t.driver_id AND t.status = 'completed'
             LEFT JOIN driver_ratings dr ON dr.driver_id = u.id
             WHERE u.role = 'driver'
             GROUP BY u.id, u.name, u.phone
             ORDER BY total_earnings DESC
             LIMIT $1`,
            [limit]
        );

        res.json({
            top_drivers: result.rows.map(r => ({
                ...r,
                total_earnings: parseFloat(r.total_earnings),
                avg_rating:     parseFloat(parseFloat(r.avg_rating).toFixed(2))
            }))
        });
    } catch (err) {
        console.error('Top drivers error:', err);
        res.status(500).json({ error: 'Failed to fetch top drivers.' });
    }
});

router.get('/reports/trip-status', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT
                status,
                COUNT(*)::int                        AS count,
                COALESCE(SUM(fare), 0)               AS total_fare
             FROM trips
             GROUP BY status
             ORDER BY count DESC`
        );

        res.json({
            distribution: result.rows.map(r => ({
                status:     r.status,
                count:      r.count,
                total_fare: parseFloat(r.total_fare)
            }))
        });
    } catch (err) {
        console.error('Trip status error:', err);
        res.status(500).json({ error: 'Failed to fetch trip status distribution.' });
    }
});

router.get('/reports/monthly', [
    query('year').isInt({ min: 2020, max: 2100 }),
    query('month').isInt({ min: 1, max: 12 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { year, month } = req.query;

    try {
        const summary = await pool.query(
            `SELECT
                COUNT(*) FILTER (WHERE status = 'completed')::int        AS completed_trips,
                COUNT(*) FILTER (WHERE status = 'cancelled')::int         AS cancelled_trips,
                COALESCE(SUM(fare) FILTER (WHERE status = 'completed'), 0) AS total_revenue,
                COALESCE(SUM(fare * 0.20) FILTER (WHERE status = 'completed'), 0) AS total_commission,
                COUNT(DISTINCT member_id)::int                            AS unique_members,
                COUNT(DISTINCT driver_id)::int                            AS unique_drivers
             FROM trips
             WHERE EXTRACT(YEAR  FROM created_at) = $1
               AND EXTRACT(MONTH FROM created_at) = $2`,
            [year, month]
        );

        const daily = await pool.query(
            `SELECT
                DATE(completed_at) AS date,
                COUNT(*)::int       AS trips,
                COALESCE(SUM(fare), 0) AS revenue,
                COALESCE(SUM(fare * 0.20), 0) AS commission
             FROM trips
             WHERE status = 'completed'
               AND EXTRACT(YEAR  FROM completed_at) = $1
               AND EXTRACT(MONTH FROM completed_at) = $2
             GROUP BY DATE(completed_at)
             ORDER BY date ASC`,
            [year, month]
        );

        const s = summary.rows[0];
        res.json({
            period: `${year}-${String(month).padStart(2, '0')}`,
            summary: {
                completed_trips:  s.completed_trips,
                cancelled_trips:  s.cancelled_trips,
                total_revenue:    parseFloat(s.total_revenue),
                total_commission: parseFloat(s.total_commission),
                unique_members:   s.unique_members,
                unique_drivers:   s.unique_drivers
            },
            daily: daily.rows.map(r => ({
                date:       r.date,
                trips:      r.trips,
                revenue:    parseFloat(r.revenue),
                commission: parseFloat(r.commission)
            }))
        });
    } catch (err) {
        console.error('Monthly report error:', err);
        res.status(500).json({ error: 'Failed to fetch monthly report.' });
    }
});

// ========================
// TRIP MONITORING
// ========================

router.get('/trips/all', [
    query('status').optional().isIn(['pending', 'accepted', 'ongoing', 'completed', 'cancelled']),
    query('date_from').optional().isISO8601(),
    query('date_to').optional().isISO8601(),
    query('limit').optional().isInt({ min: 1, max: 200 }),
    query('offset').optional().isInt({ min: 0 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { status, date_from, date_to, limit = 50, offset = 0 } = req.query;
    const params = [];
    const conditions = [];

    if (status) {
        params.push(status);
        conditions.push(`t.status = $${params.length}`);
    }
    if (date_from) {
        params.push(date_from);
        conditions.push(`t.created_at >= $${params.length}`);
    }
    if (date_to) {
        params.push(date_to);
        conditions.push(`t.created_at <= $${params.length}`);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    params.push(parseInt(limit), parseInt(offset));

    try {
        const result = await pool.query(
            `SELECT t.*,
                    m.name AS member_name, m.phone AS member_phone,
                    d.name AS driver_name, d.phone AS driver_phone
             FROM trips t
             LEFT JOIN users m ON t.member_id = m.id
             LEFT JOIN users d ON t.driver_id = d.id
             ${whereClause}
             ORDER BY t.created_at DESC
             LIMIT $${params.length - 1} OFFSET $${params.length}`,
            params
        );
        res.json({ trips: result.rows });
    } catch (err) {
        console.error('All trips error:', err);
        res.status(500).json({ error: 'Failed to fetch trips.' });
    }
});

router.post('/trips/:tripId/force-cancel', [
    body('reason').trim().notEmpty().withMessage('Cancellation reason required')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { tripId } = req.params;
    const { reason } = req.body;
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        const tripResult = await client.query(
            `SELECT * FROM trips WHERE id = $1 AND status NOT IN ('completed', 'cancelled') FOR UPDATE`,
            [tripId]
        );

        if (tripResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Trip not found or already finalised.' });
        }

        const trip = tripResult.rows[0];

        await client.query(
            `UPDATE trips
             SET status = 'cancelled', cancelled_at = NOW(),
                 cancellation_reason = $1, updated_at = NOW()
             WHERE id = $2`,
            [`[Admin] ${reason}`, tripId]
        );

        if (trip.driver_id) {
            await client.query(
                `UPDATE driver_status SET is_available = true, current_trip_id = NULL
                 WHERE driver_id = $1`,
                [trip.driver_id]
            );
        }

        await client.query('COMMIT');

        res.json({ success: true, message: 'Trip force-cancelled by admin.' });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Force cancel error:', err);
        res.status(500).json({ error: 'Failed to cancel trip.' });
    } finally {
        client.release();
    }
});

// ========================
// SYSTEM SETTINGS
// ========================

router.get('/settings', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT key, value, description, updated_at FROM system_settings ORDER BY key`
        );
        res.json({ settings: result.rows });
    } catch (err) {
        console.error('Get settings error:', err);
        res.status(500).json({ error: 'Failed to fetch settings.' });
    }
});

router.put('/settings/:key', [
    body('value').notEmpty().withMessage('Value required'),
    body('description').optional().trim()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { key } = req.params;
    const { value, description } = req.body;

    try {
        const result = await pool.query(
            `INSERT INTO system_settings (key, value, description)
             VALUES ($1, $2, $3)
             ON CONFLICT (key) DO UPDATE
             SET value       = $2,
                 description = COALESCE($3, system_settings.description),
                 updated_at  = NOW()
             RETURNING *`,
            [key, value, description || null]
        );
        res.json({ setting: result.rows[0] });
    } catch (err) {
        console.error('Update setting error:', err);
        res.status(500).json({ error: 'Failed to update setting.' });
    }
});

// ========================
// SURGE PRICING MANAGEMENT
// ========================

router.get('/surge-pricing', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT * FROM surge_pricing ORDER BY created_at DESC`
        );
        res.json({ rules: result.rows });
    } catch (err) {
        console.error('Get surge pricing error:', err);
        res.status(500).json({ error: 'Failed to fetch surge pricing.' });
    }
});

router.post('/surge-pricing', [
    body('name').trim().notEmpty().withMessage('Name required'),
    body('multiplier').isFloat({ min: 1.0, max: 10.0 }).withMessage('Multiplier must be between 1.0 and 10.0'),
    body('date').optional().isISO8601().withMessage('date must be ISO 8601'),
    body('day_of_week').optional().isInt({ min: 0, max: 6 }),
    body('start_time').optional().matches(/^\d{2}:\d{2}(:\d{2})?$/).withMessage('start_time format HH:MM'),
    body('end_time').optional().matches(/^\d{2}:\d{2}(:\d{2})?$/).withMessage('end_time format HH:MM')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { name, multiplier, date, day_of_week, start_time, end_time } = req.body;

    try {
        const result = await pool.query(
            `INSERT INTO surge_pricing
                (name, multiplier, date, day_of_week, start_time, end_time, is_active)
             VALUES ($1, $2, $3, $4, $5, $6, true)
             RETURNING *`,
            [name, multiplier, date || null, day_of_week ?? null, start_time || null, end_time || null]
        );
        res.status(201).json({ rule: result.rows[0] });
    } catch (err) {
        console.error('Create surge rule error:', err);
        res.status(500).json({ error: 'Failed to create surge rule.' });
    }
});

router.patch('/surge-pricing/:ruleId', [
    body('is_active').isBoolean().withMessage('is_active must be boolean')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { ruleId } = req.params;
    const { is_active } = req.body;

    try {
        const result = await pool.query(
            `UPDATE surge_pricing SET is_active = $1, updated_at = NOW()
             WHERE id = $2 RETURNING *`,
            [is_active, ruleId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Rule not found.' });
        }

        res.json({ rule: result.rows[0] });
    } catch (err) {
        console.error('Toggle surge rule error:', err);
        res.status(500).json({ error: 'Failed to toggle surge rule.' });
    }
});

router.delete('/surge-pricing/:ruleId', async (req, res) => {
    const { ruleId } = req.params;

    try {
        const result = await pool.query(
            `DELETE FROM surge_pricing WHERE id = $1 RETURNING id`,
            [ruleId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Rule not found.' });
        }

        res.json({ success: true });
    } catch (err) {
        console.error('Delete surge rule error:', err);
        res.status(500).json({ error: 'Failed to delete surge rule.' });
    }
});

// ========================
// BROADCASTS
// ========================

router.post('/broadcasts', [
    body('audience').isIn(['all', 'members', 'drivers']).withMessage("audience must be 'all', 'members', or 'drivers'"),
    body('message').trim().notEmpty().withMessage('Message required'),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { audience, message } = req.body;

    try {
        const result = await pool.query(
            `INSERT INTO broadcasts (admin_id, audience, message) VALUES ($1, $2, $3) RETURNING *`,
            [req.user.id, audience, message]
        );

        // Emit via Socket.IO so connected clients see it immediately
        // The io instance is not available here directly, so we store a pending broadcast
        // that the caller (server.js) can pick up, or clients poll /api/admin/broadcasts.
        // For direct socket emit, server.js wraps these routes and passes io via closure.

        res.status(201).json({ broadcast: result.rows[0] });
    } catch (err) {
        console.error('Broadcast error:', err);
        res.status(500).json({ error: 'Failed to send broadcast.' });
    }
});

router.get('/broadcasts', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT b.*, u.name AS admin_name FROM broadcasts b
             JOIN users u ON b.admin_id = u.id
             ORDER BY b.sent_at DESC LIMIT 50`
        );
        res.json({ broadcasts: result.rows });
    } catch (err) {
        console.error('Get broadcasts error:', err);
        res.status(500).json({ error: 'Failed to fetch broadcasts.' });
    }
});

// ========================
// ACTIVE TRIPS FOR MONITORING
// ========================

router.get('/trips/live', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT t.id, t.status, t.fare, t.passenger_count,
                    t.pickup_address, t.dropoff_address,
                    t.pickup_lat, t.pickup_lng, t.dropoff_lat, t.dropoff_lng,
                    t.verification_code, t.accepted_at, t.started_at,
                    m.name AS member_name, m.phone AS member_phone,
                    d.name AS driver_name, d.phone AS driver_phone,
                    ll.lat AS driver_lat, ll.lng AS driver_lng, ll.updated_at AS location_updated
             FROM trips t
             JOIN users m ON t.member_id = m.id
             LEFT JOIN users d ON t.driver_id = d.id
             LEFT JOIN live_locations ll ON t.driver_id = ll.driver_id
             WHERE t.status IN ('pending', 'accepted', 'ongoing')
             ORDER BY t.created_at DESC`
        );
        res.json({ trips: result.rows });
    } catch (err) {
        console.error('Live trips error:', err);
        res.status(500).json({ error: 'Failed to fetch live trips.' });
    }
});

// ========================
// SOS MANAGEMENT
// ========================

router.get('/sos', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT se.*, u.name AS user_name, u.phone AS user_phone
             FROM sos_events se
             JOIN users u ON se.user_id = u.id
             ORDER BY se.created_at DESC LIMIT 100`
        );
        res.json({ events: result.rows });
    } catch (err) {
        console.error('Admin SOS list error:', err);
        res.status(500).json({ error: 'Failed to fetch SOS events.' });
    }
});

router.patch('/sos/:id/resolve', async (req, res) => {
    try {
        const result = await pool.query(
            `UPDATE sos_events SET status='resolved', resolved_at=NOW()
             WHERE id=$1 RETURNING *`,
            [req.params.id]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'SOS event not found.' });
        res.json({ ok: true, event: result.rows[0] });
    } catch (err) {
        console.error('Admin SOS resolve error:', err);
        res.status(500).json({ error: 'Failed to resolve SOS event.' });
    }
});

// ========================
// DRIVER VERIFICATION (approve / reject whole driver)
// ========================

// List drivers awaiting verification
router.get('/verifications/pending', requirePerm('approveDrivers'), async (req, res) => {
    try {
        const r = await pool.query(
            `SELECT u.id, u.name, u.phone, u.email, u.verification_status, u.created_at,
                    (SELECT COUNT(*)::int FROM driver_documents d WHERE d.driver_id = u.id) AS document_count
             FROM users u
             WHERE u.role='driver' AND u.verification_status IN ('pending','rejected')
             ORDER BY u.created_at DESC`
        );
        res.json({ drivers: r.rows });
    } catch (err) {
        console.error('pending verifications error:', err);
        res.status(500).json({ error: 'Failed to fetch pending verifications.' });
    }
});

// Approve or reject a driver's overall verification
router.post('/drivers/:driverId/verify', requirePerm('approveDrivers'),
  [body('decision').isIn(['approved', 'rejected']), body('reason').optional().trim()],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const { driverId } = req.params;
    const { decision, reason } = req.body;
    try {
        const r = await pool.query(
            `UPDATE users SET verification_status=$1, updated_at=NOW()
             WHERE id=$2 AND role='driver' RETURNING id, name, verification_status`,
            [decision, driverId]
        );
        if (!r.rows[0]) return res.status(404).json({ error: 'Driver not found.' });
        // Also flip every document to match the decision for a clean state.
        await pool.query(
            `UPDATE driver_documents SET status=$1, notes=$2, reviewer_id=$3, reviewed_at=NOW(), updated_at=NOW()
             WHERE driver_id=$4`,
            [decision, reason || null, req.user.id, driverId]
        );
        await audit(req, 'verify_driver', driverId, `${decision}${reason ? ': ' + reason : ''}`);

        const io = req.app.get('io');
        if (io) io.to(`user_${driverId}`).emit('driver:verification_result', { status: decision, reason });

        res.json({ driver: r.rows[0] });
    } catch (err) {
        console.error('verify driver error:', err);
        res.status(500).json({ error: 'Failed to update verification.' });
    }
});

// ========================
// ROUTE REQUESTS (from members & drivers)
// ========================
router.get('/route-requests', async (req, res) => {
    try {
        const r = await pool.query(
            `SELECT rr.*, u.name AS requester_name, u.phone AS requester_phone
             FROM route_requests rr
             JOIN users u ON rr.requested_by = u.id
             ORDER BY rr.created_at DESC LIMIT 200`
        );
        res.json({ requests: r.rows });
    } catch (err) {
        console.error('route requests error:', err);
        res.status(500).json({ error: 'Failed to fetch route requests.' });
    }
});

router.patch('/route-requests/:id', requirePerm('manageUsers'),
  [body('status').isIn(['pending', 'reviewing', 'published', 'declined'])],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    try {
        const r = await pool.query(
            `UPDATE route_requests SET status=$1 WHERE id=$2 RETURNING *`,
            [req.body.status, req.params.id]
        );
        if (!r.rows[0]) return res.status(404).json({ error: 'Request not found.' });
        await audit(req, 'route_request_' + req.body.status, req.params.id);
        res.json({ request: r.rows[0] });
    } catch (err) {
        console.error('update route request error:', err);
        res.status(500).json({ error: 'Failed to update request.' });
    }
});

// ========================
// AUDIT LOG
// ========================
router.get('/audit-log', async (req, res) => {
    try {
        const r = await pool.query(
            `SELECT id, actor_name, action, target, detail, created_at
             FROM audit_log ORDER BY created_at DESC LIMIT 200`
        );
        res.json({ entries: r.rows });
    } catch (err) {
        // audit table may not exist yet
        res.json({ entries: [] });
    }
});

// ========================
// STAFF MANAGEMENT (super_admin only)
// ========================
router.get('/staff', requirePerm('manageStaff'), async (req, res) => {
    try {
        const r = await pool.query(
            `SELECT id, name, phone, email, staff_role, is_active, created_at
             FROM users WHERE role='admin' ORDER BY created_at ASC`
        );
        res.json({ staff: r.rows });
    } catch (err) {
        console.error('list staff error:', err);
        res.status(500).json({ error: 'Failed to fetch staff.' });
    }
});

router.patch('/staff/:userId/role', requirePerm('manageStaff'),
  [body('staffRole').isIn(['super_admin', 'operations', 'support', 'finance'])],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    try {
        const r = await pool.query(
            `UPDATE users SET staff_role=$1, updated_at=NOW() WHERE id=$2 AND role='admin'
             RETURNING id, name, staff_role`,
            [req.body.staffRole, req.params.userId]
        );
        if (!r.rows[0]) return res.status(404).json({ error: 'Staff member not found.' });
        await audit(req, 'set_staff_role', req.params.userId, req.body.staffRole);
        res.json({ staff: r.rows[0] });
    } catch (err) {
        console.error('set staff role error:', err);
        res.status(500).json({ error: 'Failed to update staff role.' });
    }
});

// ========================
// PLATFORM RESET (super_admin only — destructive)
// ========================
router.post('/platform/reset', requirePerm('resetPlatform'),
  [body('confirm').equals('RESET'), body('scope').optional().isIn(['trips', 'all'])],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ error: 'Type RESET to confirm this destructive action.' });
    const scope = req.body.scope || 'trips';
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        // Always safe to clear operational data
        await client.query('DELETE FROM trip_messages');
        await client.query('DELETE FROM route_history');
        await client.query('DELETE FROM live_locations');
        await client.query('DELETE FROM sos_events');
        await client.query('DELETE FROM trips');
        if (scope === 'all') {
            await client.query('DELETE FROM wallet_transactions');
            await client.query('DELETE FROM withdrawals');
            await client.query('DELETE FROM route_requests');
            await client.query("UPDATE users SET wallet_balance=0 WHERE role IN ('member','driver')");
        }
        await client.query('COMMIT');
        await audit(req, 'platform_reset', null, `scope=${scope}`);
        res.json({ ok: true, scope });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('platform reset error:', err);
        res.status(500).json({ error: 'Reset failed.' });
    } finally {
        client.release();
    }
});

module.exports = router;
