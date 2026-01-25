INSERT INTO users (id, school_id, email, password_hash, first_name, last_name, created_at, updated_at)
VALUES
  ('22222222-2222-2222-2222-222222222221', '11111111-1111-1111-1111-111111111111', 'admin@demo.local', 'dev_password_hash', 'Admin', 'User', now(), now()),
  ('22222222-2222-2222-2222-222222222222', '11111111-1111-1111-1111-111111111111', 'teacher@demo.local', 'dev_password_hash', 'Taylor', 'Teacher', now(), now()),
  ('22222222-2222-2222-2222-222222222223', '11111111-1111-1111-1111-111111111111', 'student@demo.local', 'dev_password_hash', 'Sam', 'Student', now(), now()),
  ('22222222-2222-2222-2222-222222222224', '11111111-1111-1111-1111-111111111111', 'dev@demo.local', 'dev_password_hash', 'Dev', 'User', now(), now());

INSERT INTO administrators (user_id, role, created_at)
VALUES ('22222222-2222-2222-2222-222222222221', 'super_admin', now());

INSERT INTO teachers (user_id, created_at)
VALUES ('22222222-2222-2222-2222-222222222222', now());

INSERT INTO students (user_id, student_number, created_at)
VALUES ('22222222-2222-2222-2222-222222222223', 'S-0001', now());

INSERT INTO developers (user_id, created_at)
VALUES ('22222222-2222-2222-2222-222222222224', now());

INSERT INTO student_devices (id, student_id, device_identifier, public_key, registered_at, active)
VALUES ('33333333-3333-3333-3333-333333333331', '22222222-2222-2222-2222-222222222223', 'demo-device-1', NULL, now(), true);
