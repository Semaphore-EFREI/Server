ALTER TABLE school_preferences
  ADD COLUMN IF NOT EXISTS enable_qrcode boolean NOT NULL DEFAULT true;

ALTER TABLE school_preferences
  DROP COLUMN IF EXISTS disable_course_modification_from_ui;
