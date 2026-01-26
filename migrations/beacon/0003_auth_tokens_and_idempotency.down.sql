DROP TABLE IF EXISTS beacon_idempotency_keys;
DROP TABLE IF EXISTS beacon_tokens;
ALTER TABLE beacons DROP COLUMN IF EXISTS deleted_at;
