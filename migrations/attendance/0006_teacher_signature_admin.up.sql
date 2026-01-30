ALTER TABLE teacher_signatures
  ADD COLUMN IF NOT EXISTS administrator_id uuid;
