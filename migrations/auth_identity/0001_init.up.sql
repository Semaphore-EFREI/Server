CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TYPE admin_role AS ENUM ('super_admin', 'school_admin');

CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  school_id uuid NOT NULL,
  email text NOT NULL,
  password_hash text NOT NULL,
  first_name text NOT NULL,
  last_name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX ux_users_email ON users (email);

CREATE TABLE students (
  user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  student_number text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX ux_students_student_number ON students (student_number);

CREATE TABLE teachers (
  user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE administrators (
  user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  role admin_role NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE developers (
  user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE refresh_token_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  user_agent text,
  ip_address text
);

CREATE INDEX ix_refresh_token_sessions_user_id ON refresh_token_sessions (user_id);

CREATE TABLE student_devices (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  student_id uuid NOT NULL REFERENCES students(user_id) ON DELETE CASCADE,
  device_identifier text NOT NULL,
  public_key text,
  registered_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz,
  revoked_at timestamptz,
  active boolean NOT NULL DEFAULT true
);

CREATE UNIQUE INDEX ux_student_devices_device_identifier ON student_devices (device_identifier);
CREATE UNIQUE INDEX ux_student_devices_active ON student_devices (student_id) WHERE active;
CREATE INDEX ix_student_devices_student_id ON student_devices (student_id);
