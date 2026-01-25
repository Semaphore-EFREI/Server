CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE school_preferences (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  default_signature_closing_delay_minutes integer NOT NULL,
  teacher_can_modify_closing_delay boolean NOT NULL,
  students_can_sign_before_teacher boolean NOT NULL,
  enable_flash boolean NOT NULL,
  enable_qrcode boolean NOT NULL,
  enable_nfc boolean NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE schools (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  preferences_id uuid NOT NULL REFERENCES school_preferences(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE classrooms (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  school_id uuid NOT NULL REFERENCES schools(id) ON DELETE CASCADE,
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ix_classrooms_school_id ON classrooms (school_id);

CREATE TABLE courses (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  school_id uuid NOT NULL REFERENCES schools(id) ON DELETE CASCADE,
  name text NOT NULL,
  start_at timestamptz NOT NULL,
  end_at timestamptz NOT NULL,
  is_online boolean NOT NULL,
  signature_closing_delay_minutes integer NOT NULL,
  signature_closed boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ix_courses_school_id ON courses (school_id);

CREATE TABLE student_groups (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  school_id uuid NOT NULL REFERENCES schools(id) ON DELETE CASCADE,
  name text NOT NULL,
  single_student_group boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ix_student_groups_school_id ON student_groups (school_id);

CREATE TABLE students_groups (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  student_id uuid NOT NULL,
  student_group_id uuid NOT NULL REFERENCES student_groups(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX ux_students_groups_unique ON students_groups (student_id, student_group_id);

CREATE TABLE teachers_courses (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  teacher_id uuid NOT NULL,
  course_id uuid NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX ux_teachers_courses_unique ON teachers_courses (teacher_id, course_id);

CREATE TABLE courses_student_groups (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  course_id uuid NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
  student_group_id uuid NOT NULL REFERENCES student_groups(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX ux_courses_student_groups_unique ON courses_student_groups (course_id, student_group_id);

CREATE TABLE courses_classrooms (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  course_id uuid NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
  classroom_id uuid NOT NULL REFERENCES classrooms(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX ux_courses_classrooms_unique ON courses_classrooms (course_id, classroom_id);
