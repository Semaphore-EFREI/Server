-- name: CreateSchoolPreferences :one
INSERT INTO school_preferences (
  id,
  default_signature_closing_delay_minutes,
  teacher_can_modify_closing_delay,
  students_can_sign_before_teacher,
  enable_flash,
  disable_course_modification_from_ui,
  enable_nfc,
  created_at,
  updated_at
) VALUES (
  $1,
  $2,
  $3,
  $4,
  $5,
  $6,
  $7,
  $8,
  $9
) RETURNING id, default_signature_closing_delay_minutes, teacher_can_modify_closing_delay, students_can_sign_before_teacher, enable_flash, disable_course_modification_from_ui, enable_nfc, created_at, updated_at, deleted_at;

-- name: GetSchoolPreferences :one
SELECT id, default_signature_closing_delay_minutes, teacher_can_modify_closing_delay, students_can_sign_before_teacher, enable_flash, disable_course_modification_from_ui, enable_nfc, created_at, updated_at, deleted_at
FROM school_preferences
WHERE id = $1 AND deleted_at IS NULL;

-- name: UpdateSchoolPreferences :one
UPDATE school_preferences
SET default_signature_closing_delay_minutes = $2,
    teacher_can_modify_closing_delay = $3,
    students_can_sign_before_teacher = $4,
    enable_flash = $5,
    disable_course_modification_from_ui = $6,
    enable_nfc = $7,
    updated_at = $8
WHERE id = $1 AND deleted_at IS NULL
RETURNING id, default_signature_closing_delay_minutes, teacher_can_modify_closing_delay, students_can_sign_before_teacher, enable_flash, disable_course_modification_from_ui, enable_nfc, created_at, updated_at, deleted_at;

-- name: CreateSchool :one
INSERT INTO schools (id, name, preferences_id, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, name, preferences_id, created_at, updated_at, deleted_at;

-- name: GetSchool :one
SELECT id, name, preferences_id, created_at, updated_at, deleted_at
FROM schools
WHERE id = $1 AND deleted_at IS NULL;

-- name: ListSchools :many
SELECT id, name, preferences_id, created_at, updated_at, deleted_at
FROM schools
WHERE deleted_at IS NULL
ORDER BY created_at DESC
LIMIT $1;

-- name: UpdateSchool :one
UPDATE schools
SET name = $2,
    updated_at = $3
WHERE id = $1 AND deleted_at IS NULL
RETURNING id, name, preferences_id, created_at, updated_at, deleted_at;

-- name: SoftDeleteSchool :exec
UPDATE schools
SET deleted_at = $2
WHERE id = $1 AND deleted_at IS NULL;

-- name: SoftDeleteSchoolPreferences :exec
UPDATE school_preferences
SET deleted_at = $2
WHERE id = $1 AND deleted_at IS NULL;

-- name: CreateClassroom :one
INSERT INTO classrooms (id, school_id, name, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, school_id, name, created_at, updated_at, deleted_at;

-- name: GetClassroom :one
SELECT id, school_id, name, created_at, updated_at, deleted_at
FROM classrooms
WHERE id = $1 AND deleted_at IS NULL;

-- name: ListClassroomsBySchool :many
SELECT id, school_id, name, created_at, updated_at, deleted_at
FROM classrooms
WHERE school_id = $1 AND deleted_at IS NULL
ORDER BY created_at DESC
LIMIT $2;

-- name: UpdateClassroom :one
UPDATE classrooms
SET name = $2,
    updated_at = $3
WHERE id = $1 AND deleted_at IS NULL
RETURNING id, school_id, name, created_at, updated_at, deleted_at;

-- name: SoftDeleteClassroom :exec
UPDATE classrooms
SET deleted_at = $2
WHERE id = $1 AND deleted_at IS NULL;

-- name: CreateCourse :one
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
  $1,
  $2,
  $3,
  $4,
  $5,
  $6,
  $7,
  $8,
  $9,
  $10
)
RETURNING id, school_id, name, start_at, end_at, is_online, signature_closing_delay_minutes, signature_closed, created_at, updated_at, deleted_at;

-- name: GetCourse :one
SELECT id, school_id, name, start_at, end_at, is_online, signature_closing_delay_minutes, signature_closed, created_at, updated_at, deleted_at
FROM courses
WHERE id = $1 AND deleted_at IS NULL;

-- name: ListCoursesBySchool :many
SELECT id, school_id, name, start_at, end_at, is_online, signature_closing_delay_minutes, signature_closed, created_at, updated_at, deleted_at
FROM courses
WHERE school_id = $1 AND deleted_at IS NULL
ORDER BY start_at DESC
LIMIT $2;

-- name: ListCoursesByTeacher :many
SELECT c.id, c.school_id, c.name, c.start_at, c.end_at, c.is_online, c.signature_closing_delay_minutes, c.signature_closed, c.created_at, c.updated_at, c.deleted_at
FROM courses c
INNER JOIN teachers_courses tc ON tc.course_id = c.id
WHERE tc.teacher_id = $1 AND c.deleted_at IS NULL
ORDER BY c.start_at DESC
LIMIT $2;

-- name: ListCoursesByStudent :many
SELECT c.id, c.school_id, c.name, c.start_at, c.end_at, c.is_online, c.signature_closing_delay_minutes, c.signature_closed, c.created_at, c.updated_at, c.deleted_at
FROM courses c
INNER JOIN courses_student_groups csg ON csg.course_id = c.id
INNER JOIN students_groups sg ON sg.student_group_id = csg.student_group_id
WHERE sg.student_id = $1 AND c.deleted_at IS NULL
ORDER BY c.start_at DESC
LIMIT $2;

-- name: ListCoursesByStudentWithinRange :many
SELECT c.id, c.school_id, c.name, c.start_at, c.end_at, c.is_online, c.signature_closing_delay_minutes, c.signature_closed, c.created_at, c.updated_at, c.deleted_at
FROM courses c
INNER JOIN courses_student_groups csg ON csg.course_id = c.id
INNER JOIN students_groups sg ON sg.student_group_id = csg.student_group_id
WHERE sg.student_id = $1
  AND c.deleted_at IS NULL
  AND c.start_at::date BETWEEN $2 AND $3
ORDER BY c.start_at DESC
LIMIT $4;

-- name: ListCoursesByTeacherWithinRange :many
SELECT c.id, c.school_id, c.name, c.start_at, c.end_at, c.is_online, c.signature_closing_delay_minutes, c.signature_closed, c.created_at, c.updated_at, c.deleted_at
FROM courses c
INNER JOIN teachers_courses tc ON tc.course_id = c.id
WHERE tc.teacher_id = $1
  AND c.deleted_at IS NULL
  AND c.start_at::date BETWEEN $2 AND $3
ORDER BY c.start_at DESC
LIMIT $4;

-- name: ListCoursesBySchoolWithinRange :many
SELECT id, school_id, name, start_at, end_at, is_online, signature_closing_delay_minutes, signature_closed, created_at, updated_at, deleted_at
FROM courses
WHERE school_id = $1
  AND deleted_at IS NULL
  AND start_at::date BETWEEN $2 AND $3
ORDER BY start_at DESC
LIMIT $4;

-- name: UpdateCourse :one
UPDATE courses
SET name = $2,
    start_at = $3,
    end_at = $4,
    is_online = $5,
    signature_closing_delay_minutes = $6,
    signature_closed = $7,
    updated_at = $8
WHERE id = $1 AND deleted_at IS NULL
RETURNING id, school_id, name, start_at, end_at, is_online, signature_closing_delay_minutes, signature_closed, created_at, updated_at, deleted_at;

-- name: SoftDeleteCourse :exec
UPDATE courses
SET deleted_at = $2
WHERE id = $1 AND deleted_at IS NULL;

-- name: CreateStudentGroup :one
INSERT INTO student_groups (id, school_id, name, single_student_group, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, school_id, name, single_student_group, created_at, updated_at, deleted_at;

-- name: GetStudentGroup :one
SELECT id, school_id, name, single_student_group, created_at, updated_at, deleted_at
FROM student_groups
WHERE id = $1 AND deleted_at IS NULL;

-- name: ListStudentGroupsBySchool :many
SELECT id, school_id, name, single_student_group, created_at, updated_at, deleted_at
FROM student_groups
WHERE school_id = $1 AND deleted_at IS NULL
ORDER BY created_at DESC
LIMIT $2;

-- name: UpdateStudentGroup :one
UPDATE student_groups
SET name = $2,
    single_student_group = $3,
    updated_at = $4
WHERE id = $1 AND deleted_at IS NULL
RETURNING id, school_id, name, single_student_group, created_at, updated_at, deleted_at;

-- name: SoftDeleteStudentGroup :exec
UPDATE student_groups
SET deleted_at = $2
WHERE id = $1 AND deleted_at IS NULL;

-- name: AddStudentGroupMembers :exec
INSERT INTO students_groups (id, student_id, student_group_id, created_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (student_id, student_group_id) DO NOTHING;

-- name: RemoveStudentGroupMember :exec
DELETE FROM students_groups
WHERE student_group_id = $1 AND student_id = $2;

-- name: AddCourseStudentGroup :exec
INSERT INTO courses_student_groups (id, course_id, student_group_id, created_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (course_id, student_group_id) DO NOTHING;

-- name: RemoveCourseStudentGroup :exec
DELETE FROM courses_student_groups
WHERE course_id = $1 AND student_group_id = $2;

-- name: AddCourseClassroom :exec
INSERT INTO courses_classrooms (id, course_id, classroom_id, created_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (course_id, classroom_id) DO NOTHING;

-- name: RemoveCourseClassroom :exec
DELETE FROM courses_classrooms
WHERE course_id = $1 AND classroom_id = $2;

-- name: AddCourseTeacher :exec
INSERT INTO teachers_courses (id, teacher_id, course_id, created_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (teacher_id, course_id) DO NOTHING;

-- name: RemoveCourseTeacher :exec
DELETE FROM teachers_courses
WHERE teacher_id = $1 AND course_id = $2;

-- name: ValidateTeacherCourse :one
SELECT EXISTS (
  SELECT 1
  FROM teachers_courses
  WHERE teacher_id = $1 AND course_id = $2
) AS is_assigned;

-- name: ValidateStudentCourse :one
SELECT EXISTS (
  SELECT 1
  FROM courses_student_groups csg
  INNER JOIN students_groups sg ON sg.student_group_id = csg.student_group_id
  WHERE sg.student_id = $1 AND csg.course_id = $2
) AS is_allowed;

-- name: ListMatchedStudentCourseGroups :many
SELECT csg.student_group_id
FROM courses_student_groups csg
INNER JOIN students_groups sg ON sg.student_group_id = csg.student_group_id
WHERE sg.student_id = $1 AND csg.course_id = $2;

-- name: ValidateClassroomCourse :one
SELECT EXISTS (
  SELECT 1
  FROM courses_classrooms
  WHERE classroom_id = $1 AND course_id = $2
) AS is_linked;

-- name: ListClassroomsByCourse :many
SELECT c.id, c.school_id, c.name, c.created_at, c.updated_at, c.deleted_at
FROM classrooms c
INNER JOIN courses_classrooms cc ON cc.classroom_id = c.id
WHERE cc.course_id = $1 AND c.deleted_at IS NULL
ORDER BY c.created_at DESC;

-- name: ListCoursesByStudentGroup :many
SELECT c.id, c.school_id, c.name, c.start_at, c.end_at, c.is_online, c.signature_closing_delay_minutes, c.signature_closed, c.created_at, c.updated_at, c.deleted_at
FROM courses c
INNER JOIN courses_student_groups csg ON csg.course_id = c.id
WHERE csg.student_group_id = $1 AND c.deleted_at IS NULL
ORDER BY c.start_at DESC;

-- name: ListStudentIDsByStudentGroup :many
SELECT student_id
FROM students_groups
WHERE student_group_id = $1;

-- name: ListStudentGroupsByCourse :many
SELECT sg.id, sg.school_id, sg.name, sg.single_student_group, sg.created_at, sg.updated_at, sg.deleted_at
FROM student_groups sg
INNER JOIN courses_student_groups csg ON csg.student_group_id = sg.id
WHERE csg.course_id = $1 AND sg.deleted_at IS NULL
ORDER BY sg.created_at DESC;
