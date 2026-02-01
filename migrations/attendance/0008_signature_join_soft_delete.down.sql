DROP INDEX IF EXISTS ux_student_signatures_course_student;
DROP INDEX IF EXISTS ux_teacher_signatures_course_teacher;

CREATE UNIQUE INDEX ux_student_signatures_course_student
  ON student_signatures (course_id, student_id);

CREATE UNIQUE INDEX ux_teacher_signatures_course_teacher
  ON teacher_signatures (course_id, teacher_id);

ALTER TABLE student_signatures
  DROP COLUMN IF EXISTS deleted_at;

ALTER TABLE teacher_signatures
  DROP COLUMN IF EXISTS deleted_at;
