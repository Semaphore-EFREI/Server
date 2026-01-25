INSERT INTO school_preferences (
  id,
  default_signature_closing_delay_minutes,
  teacher_can_modify_closing_delay,
  students_can_sign_before_teacher,
  enable_flash,
  enable_qrcode,
  enable_nfc,
  created_at,
  updated_at
) VALUES (
  '11111111-1111-1111-1111-111111111112',
  15,
  true,
  false,
  true,
  true,
  true,
  now(),
  now()
);

INSERT INTO schools (id, name, preferences_id, created_at, updated_at)
VALUES (
  '11111111-1111-1111-1111-111111111111',
  'Demo School',
  '11111111-1111-1111-1111-111111111112',
  now(),
  now()
);

INSERT INTO classrooms (id, school_id, name, created_at, updated_at)
VALUES (
  '11111111-1111-1111-1111-111111111113',
  '11111111-1111-1111-1111-111111111111',
  'Room 101',
  now(),
  now()
);

INSERT INTO courses (
  id,
  school_id,
  name,
  start_at,
  end_at,
  is_online,
  signature_closing_delay_minutes,
  signature_closed,
  created_at,
  updated_at
) VALUES (
  '11111111-1111-1111-1111-111111111114',
  '11111111-1111-1111-1111-111111111111',
  'Intro to Attendance',
  timestamptz '2026-01-25 09:00:00+00',
  timestamptz '2026-01-25 10:30:00+00',
  false,
  15,
  false,
  now(),
  now()
);

INSERT INTO student_groups (id, school_id, name, single_student_group, created_at, updated_at)
VALUES (
  '11111111-1111-1111-1111-111111111115',
  '11111111-1111-1111-1111-111111111111',
  'Group A',
  false,
  now(),
  now()
);

INSERT INTO students_groups (id, student_id, student_group_id, created_at)
VALUES (
  '44444444-4444-4444-4444-444444444442',
  '22222222-2222-2222-2222-222222222223',
  '11111111-1111-1111-1111-111111111115',
  now()
);

INSERT INTO teachers_courses (id, teacher_id, course_id, created_at)
VALUES (
  '44444444-4444-4444-4444-444444444441',
  '22222222-2222-2222-2222-222222222222',
  '11111111-1111-1111-1111-111111111114',
  now()
);

INSERT INTO courses_student_groups (id, course_id, student_group_id, created_at)
VALUES (
  '44444444-4444-4444-4444-444444444443',
  '11111111-1111-1111-1111-111111111114',
  '11111111-1111-1111-1111-111111111115',
  now()
);

INSERT INTO courses_classrooms (id, course_id, classroom_id, created_at)
VALUES (
  '44444444-4444-4444-4444-444444444444',
  '11111111-1111-1111-1111-111111111114',
  '11111111-1111-1111-1111-111111111113',
  now()
);
