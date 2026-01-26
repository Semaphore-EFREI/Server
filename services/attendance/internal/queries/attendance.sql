-- name: CreateSignature :one
INSERT INTO signatures (
  id,
  course_id,
  signed_at,
  status,
  method,
  image_url,
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
  $8
)
RETURNING id, course_id, signed_at, status, method, image_url, created_at, updated_at, deleted_at;

-- name: UpdateSignature :one
UPDATE signatures
SET status = $2,
    method = $3,
    image_url = $4,
    signed_at = $5,
    updated_at = $6
WHERE id = $1 AND deleted_at IS NULL
RETURNING id, course_id, signed_at, status, method, image_url, created_at, updated_at, deleted_at;

-- name: SoftDeleteSignature :exec
UPDATE signatures
SET deleted_at = $2,
    updated_at = $2
WHERE id = $1 AND deleted_at IS NULL;

-- name: GetStudentSignature :one
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
WHERE s.id = $1 AND s.deleted_at IS NULL;

-- name: GetTeacherSignature :one
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
WHERE s.id = $1 AND s.deleted_at IS NULL;

-- name: CreateStudentSignature :exec
INSERT INTO student_signatures (signature_id, student_id, teacher_id, administrator_id, course_id)
VALUES ($1, $2, $3, $4, $5);

-- name: CreateTeacherSignature :exec
INSERT INTO teacher_signatures (signature_id, teacher_id, course_id)
VALUES ($1, $2, $3);

-- name: UpdateStudentSignature :exec
UPDATE student_signatures
SET teacher_id = $2,
    administrator_id = $3
WHERE signature_id = $1;
