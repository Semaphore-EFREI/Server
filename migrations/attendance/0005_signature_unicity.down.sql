DROP INDEX IF EXISTS ux_student_signatures_course_student;
DROP INDEX IF EXISTS ux_teacher_signatures_course_teacher;

ALTER TABLE student_signatures
  DROP COLUMN IF EXISTS course_id;

ALTER TABLE teacher_signatures
  DROP COLUMN IF EXISTS course_id;
