CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE beacons (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  serial_number text NOT NULL,
  signature_key text NOT NULL,
  totp_key text,
  classroom_id uuid,
  program_version text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz
);

CREATE UNIQUE INDEX ux_beacons_serial_number ON beacons (serial_number);
