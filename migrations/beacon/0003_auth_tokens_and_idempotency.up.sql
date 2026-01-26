ALTER TABLE beacons
  ADD COLUMN deleted_at timestamptz;

CREATE TABLE beacon_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  beacon_id uuid NOT NULL REFERENCES beacons(id) ON DELETE CASCADE,
  token_hash text NOT NULL,
  refresh_token_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  refresh_expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  last_used_at timestamptz
);

CREATE UNIQUE INDEX ux_beacon_tokens_token_hash ON beacon_tokens (token_hash);
CREATE UNIQUE INDEX ux_beacon_tokens_refresh_hash ON beacon_tokens (refresh_token_hash);
CREATE INDEX ix_beacon_tokens_beacon_id ON beacon_tokens (beacon_id);

CREATE TABLE beacon_idempotency_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  beacon_id uuid NOT NULL REFERENCES beacons(id) ON DELETE CASCADE,
  key text NOT NULL,
  endpoint text NOT NULL,
  response_status integer NOT NULL,
  response_body text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX ux_beacon_idempotency ON beacon_idempotency_keys (beacon_id, key, endpoint);
