-- Restore signature_method enum values (no data backfill).

CREATE TYPE signature_method_old AS ENUM (
  'flash',
  'qrcode',
  'nfc',
  'beacon',
  'buzzLightyear',
  'qrCode',
  'teacher',
  'web',
  'self',
  'admin'
);

ALTER TABLE signatures
  ALTER COLUMN method TYPE signature_method_old
  USING method::text::signature_method_old;

DROP TYPE signature_method;
ALTER TYPE signature_method_old RENAME TO signature_method;
