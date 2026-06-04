/**
 * routes/driver.js
 * All driver-specific endpoints:
 *   GET  /api/driver/earnings/monthly
 *   GET  /api/driver/stats
 *   GET  /api/driver/trips/history
 *   GET  /api/driver/trips/:tripId/route
 *   GET  /api/driver/vehicles
 *   POST /api/driver/vehicles
 *   PUT  /api/driver/vehicles/:vehicleId
 *   GET  /api/driver/documents
 *   POST /api/driver/documents
 *   GET  /api/driver/surge-pricing
 */

const express = require('express');
const { body, query, validationResult } = require('express-validator');
const pool = require('../db');
const { authenticate, authorize } = require('../middleware/auth');

const router = express.Router();

// All routes in this file require a valid driver token
router.use(authenticate, authorize('driver'));

// ========================
// EARNINGS
// ========================

/**
 * GET /api/driver/earnings/monthly?year=2026&month=5
 * Returns monthly summary, daily breakdown, and rating stats.
 */
router.get('/earnings/monthly', [
    query('year').isInt({ min: 2020, max: 2100 }),
    query('month').isInt({ min: 1, max: 12 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { year, month } = req.query;
    const driverId = req.user.id;

    try {
        // Summary for the month
        const summaryResult = await pool.query(
            `SELECT
                COUNT(*) FILTER (WHERE status = 'completed')::int        AS total_trips,
                COUNT(*) FILTER (WHERE status = 'cancelled')::int         AS cancelled_trips,
                COALESCE(SUM(fare) FILTER (WHERE status = 'completed'), 0) AS total_fares,
                COALESCE(SUM(fare * 0.20) FILTER (WHERE status = 'completed'), 0) AS total_commission,
                COALESCE(SUM(fare * 0.80) FILTER (WHERE status = 'completed'), 0) AS net_earnings,
                COALESCE(AVG(fare) FILTER (WHERE status = 'completed'), 0)  AS avg_fare
             FROM trips
             WHERE driver_id = $1
               AND EXTRACT(YEAR  FROM completed_at) = $2
               AND EXTRACT(MONTH FROM completed_at) = $3`,
            [driverId, year, month]
        );

        // Rating stats for the month
        const ratingResult = await pool.query(
            `SELECT
                COALESCE(AVG(dr.rating), 0) AS avg_rating,
                COUNT(dr.id)::int            AS total_reviews
             FROM driver_ratings dr
             JOIN trips t ON dr.trip_id = t.id
             WHERE dr.driver_id = $1
               AND EXTRACT(YEAR  FROM t.completed_at) = $2
               AND EXTRACT(MONTH FROM t.completed_at) = $3`,
            [driverId, year, month]
        );

        // Daily breakdown
        const dailyResult = await pool.query(
            `SELECT
                DATE(completed_at)                                    AS date,
                COUNT(*)::int                                          AS trips,
                COALESCE(SUM(fare), 0)                                AS total_fares,
                COALESCE(SUM(fare * 0.80), 0)                        AS earnings
             FROM trips
             WHERE driver_id = $1
               AND status = 'completed'
               AND EXTRACT(YEAR  FROM completed_at) = $2
               AND EXTRACT(MONTH FROM completed_at) = $3
             GROUP BY DATE(completed_at)
             ORDER BY date ASC`,
            [driverId, year, month]
        );

        const summary = summaryResult.rows[0];

        res.json({
            period: `${year}-${String(month).padStart(2, '0')}`,
            summary: {
                total_trips:      summary.total_trips,
                cancelled_trips:  summary.cancelled_trips,
                total_fares:      parseFloat(summary.total_fares),
                total_commission: parseFloat(summary.total_commission),
                net_earnings:     parseFloat(summary.net_earnings),
                avg_fare:         parseFloat(parseFloat(summary.avg_fare).toFixed(2))
            },
            ratings: {
                avg_rating:    parseFloat(parseFloat(ratingResult.rows[0].avg_rating).toFixed(2)),
                total_reviews: ratingResult.rows[0].total_reviews
            },
            daily_breakdown: dailyResult.rows.map(r => ({
                date:        r.date,
                trips:       r.trips,
                total_fares: parseFloat(r.total_fares),
                earnings:    parseFloat(r.earnings)
            }))
        });
    } catch (err) {
        console.error('Monthly earnings error:', err);
        res.status(500).json({ error: 'Failed to fetch earnings.' });
    }
});

/**
 * GET /api/driver/stats
 * All-time stats for the driver.
 */
router.get('/stats', async (req, res) => {
    const driverId = req.user.id;

    try {
        const tripStats = await pool.query(
            `SELECT
                COUNT(*) FILTER (WHERE status = 'completed')::int          AS completed_trips,
                COUNT(*) FILTER (WHERE status = 'cancelled')::int           AS cancelled_trips,
                COALESCE(SUM(fare * 0.80) FILTER (WHERE status = 'completed'), 0) AS lifetime_earnings,
                COALESCE(AVG(fare) FILTER (WHERE status = 'completed'), 0)  AS avg_trip_fare
             FROM trips
             WHERE driver_id = $1`,
            [driverId]
        );

        const ratingStats = await pool.query(
            `SELECT
                COALESCE(AVG(rating), 0)                      AS avg_rating,
                COUNT(*)::int                                   AS total_reviews,
                COUNT(*) FILTER (WHERE rating = 5)::int        AS five_star,
                COUNT(*) FILTER (WHERE rating = 4)::int        AS four_star,
                COUNT(*) FILTER (WHERE rating <= 3)::int       AS three_or_below
             FROM driver_ratings
             WHERE driver_id = $1`,
            [driverId]
        );

        const s = tripStats.rows[0];
        const r = ratingStats.rows[0];

        res.json({
            completed_trips:  s.completed_trips,
            cancelled_trips:  s.cancelled_trips,
            lifetime_earnings: parseFloat(s.lifetime_earnings),
            avg_trip_fare:    parseFloat(parseFloat(s.avg_trip_fare).toFixed(2)),
            ratings: {
                avg_rating:    parseFloat(parseFloat(r.avg_rating).toFixed(2)),
                total_reviews: r.total_reviews,
                breakdown: {
                    five_star:      r.five_star,
                    four_star:      r.four_star,
                    three_or_below: r.three_or_below
                }
            }
        });
    } catch (err) {
        console.error('Driver stats error:', err);
        res.status(500).json({ error: 'Failed to fetch stats.' });
    }
});

// ========================
// TRIP HISTORY
// ========================

/**
 * GET /api/driver/trips/history?limit=20&offset=0
 */
router.get('/trips/history', [
    query('limit').optional().isInt({ min: 1, max: 100 }),
    query('offset').optional().isInt({ min: 0 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const limit  = parseInt(req.query.limit)  || 20;
    const offset = parseInt(req.query.offset) || 0;

    try {
        const result = await pool.query(
            `SELECT
                t.*,
                m.name AS member_name,
                m.phone AS member_phone,
                dr.rating,
                dr.comment AS rating_comment
             FROM trips t
             LEFT JOIN users m ON t.member_id = m.id
             LEFT JOIN driver_ratings dr ON dr.trip_id = t.id
             WHERE t.driver_id = $1
             ORDER BY t.created_at DESC
             LIMIT $2 OFFSET $3`,
            [req.user.id, limit, offset]
        );

        res.json({ trips: result.rows, limit, offset });
    } catch (err) {
        console.error('Trip history error:', err);
        res.status(500).json({ error: 'Failed to fetch trip history.' });
    }
});

/**
 * GET /api/driver/trips/:tripId/route
 * GPS trail recorded during the trip.
 */
router.get('/trips/:tripId/route', async (req, res) => {
    const { tripId } = req.params;

    try {
        // Verify the trip belongs to this driver
        const tripCheck = await pool.query(
            'SELECT id FROM trips WHERE id = $1 AND driver_id = $2',
            [tripId, req.user.id]
        );

        if (tripCheck.rows.length === 0) {
            return res.status(404).json({ error: 'Trip not found.' });
        }

        const result = await pool.query(
            `SELECT lat, lng, heading, speed, recorded_at
             FROM route_history
             WHERE trip_id = $1
             ORDER BY recorded_at ASC`,
            [tripId]
        );

        res.json({
            tripId,
            points:       result.rows,
            total_points: result.rows.length
        });
    } catch (err) {
        console.error('Route history error:', err);
        res.status(500).json({ error: 'Failed to fetch route.' });
    }
});

// ========================
// VEHICLE MANAGEMENT
// ========================

// ========================
// SURGE PRICING (read-only for drivers)
// ========================

/**
 * GET /api/driver/surge-pricing
 * Returns currently active surge rules so the driver knows fares are elevated.
 */
router.get('/surge-pricing', async (req, res) => {
    try {
        const now      = new Date();
        const dayOfWeek = now.getDay();
        const timeStr  = now.toTimeString().split(' ')[0];

        const result = await pool.query(
            `SELECT id, name, multiplier, date, day_of_week, start_time, end_time
             FROM surge_pricing
             WHERE is_active = true
               AND (
                 (date = CURRENT_DATE)
                 OR (day_of_week = $1 AND start_time <= $2 AND end_time >= $2)
                 OR (day_of_week = $1 AND start_time IS NULL AND end_time IS NULL)
               )
             ORDER BY multiplier DESC`,
            [dayOfWeek, timeStr]
        );

        res.json({
            active_rules:       result.rows,
            current_multiplier: result.rows.length > 0
                ? parseFloat(result.rows[0].multiplier)
                : 1.0
        });
    } catch (err) {
        console.error('Surge pricing error:', err);
        res.status(500).json({ error: 'Failed to fetch surge pricing.' });
    }
});

module.exports = router;
