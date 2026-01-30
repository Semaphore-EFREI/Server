ALTER TABLE school_preferences
  ADD COLUMN IF NOT EXISTS disable_course_modification_from_ui boolean NOT NULL DEFAULT false;

ALTER TABLE school_preferences
  DROP COLUMN IF EXISTS enable_qrcode;
