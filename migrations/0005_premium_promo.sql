-- Migration 0005: Add grants_premium flag to promo codes + seed a dev testing code
ALTER TABLE promo_codes ADD COLUMN IF NOT EXISTS grants_premium BOOLEAN NOT NULL DEFAULT FALSE;

-- Dev/testing promo code — grants premium, unlimited uses, no expiry
INSERT INTO promo_codes (code, uses_max, uses_count, expires_at, created_by_server_url, grants_premium)
VALUES ('ZEEBLE-DEV', NULL, 0, NULL, 'dev', TRUE)
ON CONFLICT (code) DO UPDATE SET grants_premium = TRUE;
