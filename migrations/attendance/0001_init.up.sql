CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TYPE signature_method AS ENUM ('flash', 'qrcode', 'nfc');
CREATE TYPE signature_status AS ENUM ('present', 'absent', 'late', 'excused', 'invalid');

CREATE TABLE signatures (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  course_id uuid NOT NULL,
  signed_at timestamptz NOT NULL,
  status signature_status NOT NULL,
  method signature_method NOT NULL,
  image_url text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ix_signatures_course_id ON signatures (course_id);
CREATE INDEX ix_signatures_signed_at ON signatures (signed_at);

CREATE TABLE student_signatures (
  signature_id uuid PRIMARY KEY REFERENCES signatures(id) ON DELETE CASCADE,
  student_id uuid NOT NULL,
  teacher_id uuid,
  administrator_id uuid
);

CREATE TABLE teacher_signatures (
  signature_id uuid PRIMARY KEY REFERENCES signatures(id) ON DELETE CASCADE,
  teacher_id uuid NOT NULL
);
