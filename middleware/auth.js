const jwt = require('jsonwebtoken');
const pool = require('../db');

/**
 * authenticate — verifies the Bearer JWT and attaches req.user.
 * Pulls a fresh user row so deactivated accounts are rejected immediately
 * even if their token hasn't expired yet.
 */
const authenticate = async (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'No token provided.' });
    }

    const token = authHeader.slice(7);

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        const result = await pool.query(
            `SELECT id, role, name, phone, wallet_balance, is_active
             FROM users WHERE id = $1`,
            [decoded.id]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'User not found.' });
        }

        const user = result.rows[0];

        if (!user.is_active) {
            return res.status(403).json({ error: 'Account deactivated.' });
        }

        req.user = user;
        next();
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expired. Please login again.' });
        }
        if (err.name === 'JsonWebTokenError') {
            return res.status(401).json({ error: 'Invalid token.' });
        }
        console.error('Auth middleware error:', err);
        return res.status(500).json({ error: 'Authentication failed.' });
    }
};

/**
 * authorize(...roles) — role-based access guard, used after authenticate.
 * Usage: authorize('admin')  or  authorize('driver', 'admin')
 */
const authorize = (...roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ error: 'Not authenticated.' });
        }
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ error: 'Forbidden: insufficient permissions.' });
        }
        next();
    };
};

module.exports = { authenticate, authorize };
