-- Remove deprecated QR/flash methods from signature_method enum.

UPDATE signatures
SET method = 'buzzLightyear'
WHERE method = 'flash';

UPDATE signatures
SET method = 'web'
WHERE method IN ('qrcode', 'qrCode');

CREATE TYPE signature_method_new AS ENUM (
  'nfc',
  'beacon',
  'buzzLightyear',
  'teacher',
  'web',
  'self',
  'admin'
);

ALTER TABLE signatures
  ALTER COLUMN method TYPE signature_method_new
  USING method::text::signature_method_new;

DROP TYPE signature_method;
ALTER TYPE signature_method_new RENAME TO signature_method;
