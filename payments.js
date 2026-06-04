/**
 * routes/payments.js
 * Paystack payment integration:
 *   POST /api/payments/initialize   — create Paystack transaction
 *   GET  /api/payments/verify/:ref  — verify & credit wallet
 *   POST /api/payments/webhook      — Paystack webhook (raw body, no auth)
 *   GET  /api/payments/history      — member's payment history
 *   GET  /api/payments/admin/all    — admin: all payments
 *
 * Requires env vars:
 *   PAYSTACK_SECRET_KEY
 */

const express = require('express');
const crypto  = require('crypto');
const { body, validationResult } = require('express-validator');
const pool = require('../db');
const { authenticate, authorize } = require('../middleware/auth');

const router = express.Router();

const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET_KEY;
const PAYSTACK_BASE   = 'https://api.paystack.co';

// ========================
// HELPERS
// ========================

/**
 * Call the Paystack REST API.
 */
const paystackRequest = async (method, path, body = null) => {
    const options = {
        method,
        headers: {
            Authorization: `Bearer ${PAYSTACK_SECRET}`,
            'Content-Type': 'application/json'
        }
    };

    if (body) options.body = JSON.stringify(body);

    const response = await fetch(`${PAYSTACK_BASE}${path}`, options);
    const data = await response.json();

    if (!data.status) {
        throw new Error(data.message || 'Paystack request failed');
    }

    return data;
};

/**
 * Credit the member's wallet and record the payment — used by both
 * the verify endpoint (popup callback) and the webhook (failsafe).
 * Idempotent: uses ON CONFLICT on the unique reference column.
 */
const creditWalletForPayment = async (userId, amountKobo, reference) => {
    const amountNaira = amountKobo / 100;
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        // Idempotency check — only credit once per reference
        const existing = await client.query(
            `SELECT id FROM paystack_payments WHERE reference = $1 AND status = 'success'`,
            [reference]
        );

        if (existing.rows.length > 0) {
            await client.query('ROLLBACK');
            return { already_processed: true };
        }

        // Lock the user row and update balance
        const walletResult = await client.query(
            'SELECT wallet_balance FROM users WHERE id = $1 FOR UPDATE',
            [userId]
        );

        const newBalance = parseFloat(walletResult.rows[0].wallet_balance) + amountNaira;

        await client.query(
            'UPDATE users SET wallet_balance = $1 WHERE id = $2',
            [newBalance, userId]
        );

        // Record in wallet_transactions
        await client.query(
            `INSERT INTO wallet_transactions
                (user_id, type, amount, balance_after, description, reference_code)
             VALUES ($1, 'credit', $2, $3, $4, $5)`,
            [userId, amountNaira, newBalance, `Paystack top-up (ref: ${reference})`, reference]
        );

        // Upsert in paystack_payments (mark success)
        await client.query(
            `INSERT INTO paystack_payments (user_id, reference, amount, status)
             VALUES ($1, $2, $3, 'success')
             ON CONFLICT (reference) DO UPDATE
             SET status = 'success', updated_at = NOW()`,
            [userId, reference, amountNaira]
        );

        await client.query('COMMIT');
        return { already_processed: false, new_balance: newBalance, amount_paid: amountNaira };
    } catch (err) {
        await client.query('ROLLBACK');
        throw err;
    } finally {
        client.release();
    }
};

// ========================
// INITIALIZE PAYMENT
// ========================

/**
 * POST /api/payments/initialize
 * Body: { amount (naira), email }
 * Creates a Paystack transaction and returns the authorization_url + reference.
 */
router.post('/initialize',
    authenticate,
    authorize('member'),
    [
        body('amount').isFloat({ min: 100 }).withMessage('Minimum amount is ₦100'),
        body('email').isEmail().withMessage('Valid email required')
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

        if (!PAYSTACK_SECRET) {
            return res.status(503).json({ error: 'Payment service not configured.' });
        }

        const { amount, email } = req.body;
        const amountKobo = Math.round(parseFloat(amount) * 100);

        try {
            // Record as pending before calling Paystack (so webhook can match it)
            const reference = `KMT-${req.user.id.slice(0, 8)}-${Date.now()}`;

            await pool.query(
                `INSERT INTO paystack_payments (user_id, reference, amount, status)
                 VALUES ($1, $2, $3, 'pending')
                 ON CONFLICT (reference) DO NOTHING`,
                [req.user.id, reference, amount]
            );

            const data = await paystackRequest('POST', '/transaction/initialize', {
                email,
                amount: amountKobo,
                reference,
                metadata: { user_id: req.user.id, custom_fields: [] },
                callback_url: process.env.PAYSTACK_CALLBACK_URL || undefined
            });

            res.json({
                reference:         data.data.reference,
                authorization_url: data.data.authorization_url,
                access_code:       data.data.access_code
            });
        } catch (err) {
            console.error('Paystack initialize error:', err);
            res.status(502).json({ error: 'Failed to initialize payment: ' + err.message });
        }
    }
);

// ========================
// VERIFY PAYMENT (popup callback)
// ========================

/**
 * GET /api/payments/verify/:reference
 * Called by the frontend after the Paystack popup succeeds.
 * Verifies with Paystack, then credits wallet (idempotent).
 */
router.get('/verify/:reference', authenticate, authorize('member'), async (req, res) => {
    if (!PAYSTACK_SECRET) {
        return res.status(503).json({ error: 'Payment service not configured.' });
    }

    const { reference } = req.params;

    try {
        const data = await paystackRequest('GET', `/transaction/verify/${reference}`);
        const tx = data.data;

        if (tx.status !== 'success') {
            return res.status(402).json({ error: `Payment not successful: ${tx.gateway_response}` });
        }

        // Confirm this reference belongs to this user (stored on initialize)
        const paymentRow = await pool.query(
            'SELECT user_id FROM paystack_payments WHERE reference = $1',
            [reference]
        );

        const ownerId = paymentRow.rows[0]?.user_id;
        if (!ownerId || ownerId !== req.user.id) {
            return res.status(403).json({ error: 'Reference does not belong to your account.' });
        }

        const result = await creditWalletForPayment(req.user.id, tx.amount, reference);

        if (result.already_processed) {
            // Payment was already handled (probably via webhook); just return current balance
            const bal = await pool.query(
                'SELECT wallet_balance FROM users WHERE id = $1',
                [req.user.id]
            );
            return res.json({
                success:     true,
                amount_paid: tx.amount / 100,
                new_balance: parseFloat(bal.rows[0].wallet_balance),
                message:     'Already processed.'
            });
        }

        res.json({
            success:     true,
            amount_paid: result.amount_paid,
            new_balance: result.new_balance
        });
    } catch (err) {
        console.error('Paystack verify error:', err);
        res.status(502).json({ error: 'Verification failed: ' + err.message });
    }
});

// ========================
// WEBHOOK (Paystack → server)
// NOTE: express.raw() is applied to this path in server.js before express.json()
// ========================

/**
 * POST /api/payments/webhook
 * No authentication — validated by HMAC signature from Paystack.
 */
router.post('/webhook', async (req, res) => {
    // Always respond 200 immediately so Paystack stops retrying
    res.sendStatus(200);

    if (!PAYSTACK_SECRET) return;

    const signature = req.headers['x-paystack-signature'];
    const hash = crypto
        .createHmac('sha512', PAYSTACK_SECRET)
        .update(req.body)          // req.body is raw Buffer here
        .digest('hex');

    if (hash !== signature) {
        console.warn('Paystack webhook: invalid signature');
        return;
    }

    let event;
    try {
        event = JSON.parse(req.body.toString());
    } catch {
        console.error('Paystack webhook: failed to parse body');
        return;
    }

    if (event.event !== 'charge.success') return;

    const tx        = event.data;
    const reference = tx.reference;
    const userId    = tx.metadata?.user_id;

    if (!userId) {
        console.warn('Paystack webhook: no user_id in metadata for ref', reference);
        return;
    }

    try {
        await creditWalletForPayment(userId, tx.amount, reference);
        console.log(`✅ Webhook: wallet credited for user ${userId}, ref ${reference}`);
    } catch (err) {
        console.error('Paystack webhook credit error:', err);
    }
});

// ========================
// PAYMENT HISTORY
// ========================

/**
 * GET /api/payments/history
 * Member's own Paystack top-up history.
 */
router.get('/history', authenticate, authorize('member'), async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT reference, amount, status, created_at
             FROM paystack_payments
             WHERE user_id = $1
             ORDER BY created_at DESC
             LIMIT 50`,
            [req.user.id]
        );
        res.json({ payments: result.rows });
    } catch (err) {
        console.error('Payment history error:', err);
        res.status(500).json({ error: 'Failed to fetch payment history.' });
    }
});

/**
 * GET /api/payments/admin/all
 * Admin view of all Paystack transactions.
 */
router.get('/admin/all', authenticate, authorize('admin'), async (req, res) => {
    const { status, limit = 100, offset = 0 } = req.query;
    const params = [];
    let whereClause = '';

    if (status) {
        params.push(status);
        whereClause = `WHERE pp.status = $1`;
    }

    params.push(parseInt(limit), parseInt(offset));

    try {
        const result = await pool.query(
            `SELECT pp.*, u.name AS user_name, u.phone AS user_phone
             FROM paystack_payments pp
             JOIN users u ON pp.user_id = u.id
             ${whereClause}
             ORDER BY pp.created_at DESC
             LIMIT $${params.length - 1} OFFSET $${params.length}`,
            params
        );
        res.json({ payments: result.rows });
    } catch (err) {
        console.error('Admin payments error:', err);
        res.status(500).json({ error: 'Failed to fetch payments.' });
    }
});

module.exports = router;
