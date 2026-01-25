ALTER TABLE signatures
  ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN deleted_at timestamptz;

UPDATE signatures
SET updated_at = created_at
WHERE updated_at IS NULL;
