INSERT INTO beacons (id, serial_number, signature_key, totp_key, classroom_id, program_version, created_at, updated_at, last_seen_at)
VALUES (
  '55555555-5555-5555-5555-555555555551',
  'BEACON-0001',
  'dev-signature-key',
  NULL,
  '11111111-1111-1111-1111-111111111113',
  '0.1.0',
  now(),
  now(),
  NULL
);
