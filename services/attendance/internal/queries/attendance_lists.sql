-- name: ListStudentSignaturesByStudent :many
SELECT s.id,
       s.course_id,
       s.signed_at,
       s.status,
       s.method,
       s.image_url,
       s.created_at,
       s.updated_at,
       s.deleted_at,
       ss.student_id,
       ss.teacher_id,
       ss.administrator_id
FROM signatures s
INNER JOIN student_signatures ss ON ss.signature_id = s.id
WHERE ss.student_id = $1
  AND s.deleted_at IS NULL
ORDER BY s.signed_at DESC
LIMIT $2;

-- name: ListStudentSignaturesByStudentAndCourse :many
SELECT s.id,
       s.course_id,
       s.signed_at,
       s.status,
       s.method,
       s.image_url,
       s.created_at,
       s.updated_at,
       s.deleted_at,
       ss.student_id,
       ss.teacher_id,
       ss.administrator_id
FROM signatures s
INNER JOIN student_signatures ss ON ss.signature_id = s.id
WHERE ss.student_id = $1
  AND s.course_id = $2
  AND s.deleted_at IS NULL
ORDER BY s.signed_at DESC
LIMIT $3;

-- name: ListStudentSignaturesByCourse :many
SELECT s.id,
       s.course_id,
       s.signed_at,
       s.status,
       s.method,
       s.image_url,
       s.created_at,
       s.updated_at,
       s.deleted_at,
       ss.student_id,
       ss.teacher_id,
       ss.administrator_id
FROM signatures s
INNER JOIN student_signatures ss ON ss.signature_id = s.id
WHERE s.course_id = $1
  AND s.deleted_at IS NULL
ORDER BY s.signed_at DESC
LIMIT $2;

-- name: ListTeacherSignaturesByTeacher :many
SELECT s.id,
       s.course_id,
       s.signed_at,
       s.status,
       s.method,
       s.image_url,
       s.created_at,
       s.updated_at,
       s.deleted_at,
       ts.teacher_id
FROM signatures s
INNER JOIN teacher_signatures ts ON ts.signature_id = s.id
WHERE ts.teacher_id = $1
  AND s.deleted_at IS NULL
ORDER BY s.signed_at DESC
LIMIT $2;

-- name: ListTeacherSignaturesByCourse :many
SELECT s.id,
       s.course_id,
       s.signed_at,
       s.status,
       s.method,
       s.image_url,
       s.created_at,
       s.updated_at,
       s.deleted_at,
       ts.teacher_id
FROM signatures s
INNER JOIN teacher_signatures ts ON ts.signature_id = s.id
WHERE s.course_id = $1
  AND s.deleted_at IS NULL
ORDER BY s.signed_at DESC
LIMIT $2;

-- name: HasTeacherPresence :one
SELECT EXISTS (
  SELECT 1
  FROM signatures s
  INNER JOIN teacher_signatures ts ON ts.signature_id = s.id
  WHERE s.course_id = $1
    AND s.deleted_at IS NULL
    AND s.status IN ('present', 'signed')
) AS is_present;

-- name: CountStudentSignatureStatusByCourse :many
SELECT s.status, COUNT(*) AS total
FROM signatures s
INNER JOIN student_signatures ss ON ss.signature_id = s.id
WHERE s.course_id = $1
  AND s.deleted_at IS NULL
GROUP BY s.status;

-- name: CountTeacherSignaturesByCourse :one
SELECT COUNT(*) AS total
FROM signatures s
INNER JOIN teacher_signatures ts ON ts.signature_id = s.id
WHERE s.course_id = $1
  AND s.deleted_at IS NULL;
