ALTER TABLE student_signatures
ADD COLUMN deleted_at timestamptz;

ALTER TABLE teacher_signatures
ADD COLUMN deleted_at timestamptz;

DROP INDEX IF EXISTS ux_student_signatures_course_student;

DROP INDEX IF EXISTS ux_teacher_signatures_course_teacher;

CREATE UNIQUE INDEX ux_student_signatures_course_student ON student_signatures (course_id, student_id)
WHERE
    deleted_at IS NULL;

CREATE UNIQUE INDEX ux_teacher_signatures_course_teacher ON teacher_signatures (course_id, teacher_id)
WHERE
    deleted_at IS NULL;