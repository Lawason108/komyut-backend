-- =============================================================
-- Komyut v3 Migration — additive, safe to re-run
-- Adds columns/tables for: profiles, fleet, driver verification,
-- vehicle capacity vs preference, route requests, PIN resets,
-- staff RBAC, and an expanded document set.
-- =============================================================

-- ── USERS: profile + fleet + driver + staff columns ──────────
ALTER TABLE users ADD COLUMN IF NOT EXISTS email             TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS photo_url         TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS user_type         TEXT NOT NULL DEFAULT 'normal'
                                           CHECK (user_type IN ('normal','fleet'));
ALTER TABLE users ADD COLUMN IF NOT EXISTS company_name      TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS rating            NUMERIC(3,2) NOT NULL DEFAULT 5.0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_status TEXT NOT NULL DEFAULT 'unsubmitted'
                                           CHECK (verification_status IN ('unsubmitted','pending','approved','rejected'));
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_blocked        BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_restricted     BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS restriction_note  TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS staff_role        TEXT
                                           CHECK (staff_role IN ('super_admin','operations','support','finance'));

-- ── DRIVER VEHICLES: colour already exists; add prefs + photo ─
ALTER TABLE driver_vehicles ADD COLUMN IF NOT EXISTS seat_preference INTEGER NOT NULL DEFAULT 3;
ALTER TABLE driver_vehicles ADD COLUMN IF NOT EXISTS photo_url       TEXT;

-- ── DRIVER DOCUMENTS: widen the allowed document types ───────
-- Drop the old narrow CHECK and replace with the full set.
ALTER TABLE driver_documents DROP CONSTRAINT IF EXISTS driver_documents_document_type_check;
ALTER TABLE driver_documents ADD CONSTRAINT driver_documents_document_type_check
  CHECK (document_type IN (
    'drivers_license','vehicle_registration','roadworthiness',
    'insurance','lasrra_or_id','passport_photo','vehicle_photo',
    -- keep legacy values valid so old rows don't break
    'license','or_cr','nbi_clearance'
  ));
ALTER TABLE driver_documents ADD COLUMN IF NOT EXISTS file_name TEXT;

-- ── ROUTE REQUESTS (member + driver suggestions) ─────────────
CREATE TABLE IF NOT EXISTS route_requests (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    requested_by  UUID        NOT NULL REFERENCES users(id),
    requester_role TEXT       NOT NULL CHECK (requester_role IN ('member','driver')),
    origin        TEXT        NOT NULL,
    destination   TEXT        NOT NULL,
    preferred_time TEXT,
    days          TEXT[],
    seats         INTEGER     NOT NULL DEFAULT 1,
    notes         TEXT,
    status        TEXT        NOT NULL DEFAULT 'pending'
                              CHECK (status IN ('pending','reviewing','published','declined')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_route_requests_status ON route_requests(status);

-- ── PASSWORD / PIN RESETS (OTP) ──────────────────────────────
CREATE TABLE IF NOT EXISTS pin_resets (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID        NOT NULL REFERENCES users(id),
    code        TEXT        NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    used        BOOLEAN     NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_pin_resets_user ON pin_resets(user_id);

-- ── AUDIT LOG (admin actions) ────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL   PRIMARY KEY,
    actor_id    UUID        REFERENCES users(id),
    actor_name  TEXT,
    action      TEXT        NOT NULL,
    target      TEXT,
    detail      TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);
