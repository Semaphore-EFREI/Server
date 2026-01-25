ALTER TABLE school_preferences DROP COLUMN IF EXISTS deleted_at;
ALTER TABLE student_groups DROP COLUMN IF EXISTS deleted_at;
ALTER TABLE courses DROP COLUMN IF EXISTS deleted_at;
ALTER TABLE classrooms DROP COLUMN IF EXISTS deleted_at;
ALTER TABLE schools DROP COLUMN IF EXISTS deleted_at;
