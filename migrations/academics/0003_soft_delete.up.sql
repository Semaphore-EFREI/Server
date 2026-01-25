ALTER TABLE schools ADD COLUMN IF NOT EXISTS deleted_at timestamptz;
ALTER TABLE classrooms ADD COLUMN IF NOT EXISTS deleted_at timestamptz;
ALTER TABLE courses ADD COLUMN IF NOT EXISTS deleted_at timestamptz;
ALTER TABLE student_groups ADD COLUMN IF NOT EXISTS deleted_at timestamptz;
ALTER TABLE school_preferences ADD COLUMN IF NOT EXISTS deleted_at timestamptz;
