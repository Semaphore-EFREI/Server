INSERT INTO signatures (id, course_id, signed_at, status, method, image_url, created_at)
VALUES (
  '33333333-3333-3333-3333-333333333332',
  '11111111-1111-1111-1111-111111111114',
  timestamptz '2026-01-25 09:05:00+00',
  'present',
  'flash',
  NULL,
  now()
);

INSERT INTO student_signatures (signature_id, student_id, teacher_id, administrator_id)
VALUES (
  '33333333-3333-3333-3333-333333333332',
  '22222222-2222-2222-2222-222222222223',
  '22222222-2222-2222-2222-222222222222',
  NULL
);

INSERT INTO teacher_signatures (signature_id, teacher_id)
VALUES (
  '33333333-3333-3333-3333-333333333332',
  '22222222-2222-2222-2222-222222222222'
);
