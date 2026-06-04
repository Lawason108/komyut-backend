-- =============================================================
-- Komyut — Full Database Schema
-- Run this once in your Supabase / Neon SQL editor.
-- Safe to re-run: all statements use IF NOT EXISTS.
-- =============================================================

-- ──────────────────────────────────────────
-- EXTENSIONS
-- ──────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- for gen_random_uuid()

-- ──────────────────────────────────────────
-- USERS
-- ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    role            TEXT        NOT NULL CHECK (role IN ('member', 'driver', 'admin')),
    name            TEXT        NOT NULL,
    phone           TEXT        NOT NULL UNIQUE,
    password_hash   TEXT        NOT NULL,
    wallet_balance  NUMERIC(12, 2) NOT NULL DEFAULT 0,
    is_active       BOOLEAN     NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ──────────────────────────────────────────
-- TRIPS
-- ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS trips (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    member_id           UUID        NOT NULL REFERENCES users(id),
    driver_id           UUID        REFERENCES users(id),
    status              TEXT        NOT NULL DEFAULT 'pending'
                                    CHECK (status IN ('pending','accepted','ongoing','completed','cancelled')),
    verification_code   INTEGER     NOT NULL,
    fare                NUMERIC(10, 2) NOT NULL,
    passenger_count     INTEGER     NOT NULL DEFAULT 1,
    pickup_address      TEXT        NOT NULL,
    pickup_lat          DOUBLE PRECISION NOT NULL,
    pickup_lng          DOUBLE PRECISION NOT NULL,
    dropoff_address     TEXT        NOT NULL,
    dropoff_lat         DOUBLE PRECISION NOT NULL,
    dropoff_lng         DOUBLE PRECISION NOT NULL,
    cancellation_reason TEXT,
    accepted_at         TIMESTAMPTZ,
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    cancelled_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_trips_member_id   ON trips(member_id);
CREATE INDEX IF NOT EXISTS idx_trips_driver_id   ON trips(driver_id);
CREATE INDEX IF NOT EXISTS idx_trips_status      ON trips(status);
CREATE INDEX IF NOT EXISTS idx_trips_created_at  ON trips(created_at DESC);

-- ──────────────────────────────────────────
-- DRIVER STATUS
-- ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS driver_status (
    driver_id       UUID        PRIMARY KEY REFERENCES users(id),
    is_online       BOOLEAN     NOT NULL DEFAULT false,
    is_available    BOOLEAN     NOT NULL DEFAULT false,
    current_trip_id UUID        REFERENCES trips(id),
    last_online_at  TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ──────────────────────────────────────────
-- LIVE LOCATIONS (one row per driver, upserted)
-- ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS live_locations (
    driver_id   UUID        PRIMARY KEY REFERENCES users(id),
    lat         DOUBLE PRECISION NOT NULL,
    lng         DOUBLE PRECISION NOT NULL,
    heading     DOUBLE PRECISION,
    speed       DOUBLE PRECISION,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ──────────────────────────────────────────
-- ROUTE HISTORY (GPS trail per trip)
-- ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS route_history (
    id          BIGSERIAL   PRIMARY KEY,
    trip_id     UUID        NOT NULL REFERENCES trips(id),
    driver_id   UUID        NOT NULL REFERENCES users(id),
    lat         DOUBLE PRECISION NOT NULL,
    lng         DOUBLE PRECISION NOT NULL,
    heading     DOUBLE PRECISION,
    speed       DOUBLE PRECISION,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_route_history_trip_id ON route_history(trip_id);

-- ──────────────────────────────────────────
-- WALLET TRANSACTIONS
-- ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS wallet_transactions (
    id              BIGSERIAL   PRIMARY KEY,
    user_id         UUID        NOT NULL REFERENCES users(id),
    trip_id         UUID        REFERENCES trips(id),
    type            TEXT        NOT NULL CHECK (type IN ('credit', 'debit', 'withdrawal')),
    amount          NUMERIC(10, 2) NOT NULL,
    balance_after   NUMERIC(12, 2) NOT NULL,
    description     TEXT,
    reference_code  TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_wallet_tx_user_id    ON wallet_transactions(user_id);
CREATE INDEX IF NOT EXISTS idx_wallet_tx_created_at ON wallet_transactions(created_at DESC);

-- ──────────────────────────────────────────
-- WITHDRAWALS
-- ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS withdrawals (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    driver_id       UUID        NOT NULL REFERENCES users(id),
    amount          NUMERIC(10, 2) NOT NULL,
    method          TEXT        NOT NULL CHECK (method IN ('bank_transfer', 'gcash', 'paymaya')),
    account_details JSONB       NOT NULL,
    status          TEXT        NOT NULL DEFAULT 'pending'
                                CHECK (status IN ('pending', 'completed', 'rejected')),
    notes           TEXT,
    processed_by    UUID        REFERENCES users(id),
    processed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_withdrawals_driver_id ON withdrawals(driver_id);
CREATE INDEX IF NOT EXISTS idx_withdrawals_status    ON withdrawals(status);

-- ──────────────────────────────────────────
-- TRIP MESSAGES (in-trip chat)
-- ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS trip_messages (
    id          BIGSERIAL   PRIMARY KEY,
    trip_id     UUID        NOT NULL REFERENCES trips(id),
    sender_id   UUID        NOT NULL REFERENCES users(id),
    message     TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_trip_messages_trip_id ON trip_messages(trip_id);

-- ──────────────────────────────────────────
-- DRIVER RATINGS
-- ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS driver_ratings (
    id          BIGSERIAL   PRIMARY KEY,
    trip_id     UUID        NOT NULL UNIQUE REFERENCES trips(id),  -- one rating per trip
    driver_id   UUID        NOT NULL REFERENCES users(id),
    member_id   UUID        NOT NULL REFERENCES users(id),
    rating      INTEGER     NOT NULL CHECK (rating BETWEEN 1 AND 5),
    comment     TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_driver_ratings_driver_id ON driver_ratings(driver_id);

-- ──────────────────────────────────────────
-- DRIVER VEHICLES
-- ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS driver_vehicles (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    driver_id       UUID        NOT NULL REFERENCES users(id),
    plate_number    TEXT        NOT NULL UNIQUE,
    model           TEXT        NOT NULL,
    color           TEXT        NOT NULL,
    capacity        INTEGER     NOT NULL DEFAULT 4,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_driver_vehicles_driver_id ON driver_vehicles(driver_id);

-- ──────────────────────────────────────────
-- DRIVER DOCUMENTS
-- ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS driver_documents (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    driver_id       UUID        NOT NULL REFERENCES users(id),
    document_type   TEXT        NOT NULL
                                CHECK (document_type IN ('license', 'or_cr', 'nbi_clearance')),
    document_url    TEXT        NOT NULL,
    status          TEXT        NOT NULL DEFAULT 'pending'
                                CHECK (status IN ('pending', 'approved', 'rejected')),
    notes           TEXT,
    reviewer_id     UUID        REFERENCES users(id),
    reviewed_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (driver_id, document_type)   -- one live submission per document type
);

CREATE INDEX IF NOT EXISTS idx_driver_documents_driver_id ON driver_documents(driver_id);
CREATE INDEX IF NOT EXISTS idx_driver_documents_status    ON driver_documents(status);

-- ──────────────────────────────────────────
-- SURGE PRICING
-- ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS surge_pricing (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT        NOT NULL,
    multiplier  NUMERIC(4, 2) NOT NULL CHECK (multiplier >= 1.0),
    date        DATE,                       -- specific calendar date (e.g. holiday)
    day_of_week INTEGER CHECK (day_of_week BETWEEN 0 AND 6),  -- 0=Sun..6=Sat
    start_time  TIME,
    end_time    TIME,
    is_active   BOOLEAN     NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ──────────────────────────────────────────
-- SYSTEM SETTINGS (admin-configurable fare rules etc.)
-- ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS system_settings (
    key         TEXT        PRIMARY KEY,
    value       TEXT        NOT NULL,
    description TEXT,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed default settings (safe to re-run via ON CONFLICT DO NOTHING)
INSERT INTO system_settings (key, value, description) VALUES
    ('base_fare',             '40',   'Base fare charged for every trip'),
    ('per_km_rate',           '15',   'Additional charge per kilometre'),
    ('extra_passenger_rate',  '10',   'Per extra passenger above 1'),
    ('cancellation_fee',      '20',   'Fee charged to member for cancelling an accepted trip'),
    ('platform_commission',   '0.20', 'Platform cut from each completed trip (0.20 = 20%)')
ON CONFLICT (key) DO NOTHING;

-- ──────────────────────────────────────────
-- PAYSTACK PAYMENTS
-- ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS paystack_payments (
    id          BIGSERIAL   PRIMARY KEY,
    user_id     UUID        NOT NULL REFERENCES users(id),
    reference   TEXT        NOT NULL UNIQUE,
    amount      NUMERIC(10, 2) NOT NULL,
    status      TEXT        NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending', 'success', 'failed')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_paystack_payments_user_id   ON paystack_payments(user_id);
CREATE INDEX IF NOT EXISTS idx_paystack_payments_reference ON paystack_payments(reference);

-- ──────────────────────────────────────────
-- SOS EVENTS (added in v2 — backend + admin dashboard integration)
-- ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sos_events (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID        NOT NULL REFERENCES users(id),
    role        TEXT        NOT NULL CHECK (role IN ('member', 'driver')),
    lat         DOUBLE PRECISION,
    lng         DOUBLE PRECISION,
    status      TEXT        NOT NULL DEFAULT 'triggered'
                            CHECK (status IN ('triggered', 'acknowledged', 'resolved')),
    resolved_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sos_events_status     ON sos_events(status);
CREATE INDEX IF NOT EXISTS idx_sos_events_user_id    ON sos_events(user_id);
CREATE INDEX IF NOT EXISTS idx_sos_events_created_at ON sos_events(created_at DESC);

-- ──────────────────────────────────────────
-- BROADCASTS (admin → all users)
-- ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS broadcasts (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_id    UUID        NOT NULL REFERENCES users(id),
    audience    TEXT        NOT NULL CHECK (audience IN ('all', 'members', 'drivers')),
    message     TEXT        NOT NULL,
    sent_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_broadcasts_sent_at ON broadcasts(sent_at DESC);
