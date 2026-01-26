ALTER TABLE student_signatures
  ADD COLUMN course_id uuid;

ALTER TABLE teacher_signatures
  ADD COLUMN course_id uuid;

UPDATE student_signatures ss
SET course_id = s.course_id
FROM signatures s
WHERE s.id = ss.signature_id;

UPDATE teacher_signatures ts
SET course_id = s.course_id
FROM signatures s
WHERE s.id = ts.signature_id;

ALTER TABLE student_signatures
  ALTER COLUMN course_id SET NOT NULL;

ALTER TABLE teacher_signatures
  ALTER COLUMN course_id SET NOT NULL;

CREATE UNIQUE INDEX ux_student_signatures_course_student
  ON student_signatures (course_id, student_id);

CREATE UNIQUE INDEX ux_teacher_signatures_course_teacher
  ON teacher_signatures (course_id, teacher_id);
