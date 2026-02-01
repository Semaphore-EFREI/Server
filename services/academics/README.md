# Academics Service

This service owns school structure and planning: schools, preferences, classrooms, courses, student groups, and assignments. It exposes REST endpoints aligned with `docs/openapi.json` and a gRPC query API used by attendance.

## Responsibilities
- School + preferences CRUD
- Classroom CRUD
- Course CRUD + assignments (classrooms, groups, teachers)
- Student group CRUD + membership management
- gRPC `AcademicsQueryService`

## Local Run
Prerequisites:
- Postgres running (see repo `docker-compose.yml`)
- Migrations applied for `academics`

Run:
```
cd services/academics
DATABASE_URL="postgres://postgres:postgres@127.0.0.1:5432/academics?sslmode=disable" \
JWT_PUBLIC_KEY_FILE="/path/to/public.pem" \
JWT_ISSUER="semaphore-auth-identity" \
SERVICE_AUTH_TOKEN="dev-service-token" \
ATTENDANCE_GRPC_ADDR="127.0.0.1:9093" \
BEACON_GRPC_ADDR="127.0.0.1:9094" \
go run ./cmd/server
```

HTTP listens on `:8082`, gRPC on `:9092`.

## Configuration
- `COURSE_DURATION` (default `1h`): duration applied when creating or updating course dates.
- `COURSE_DEFAULT_RANGE_DAYS` (default `10`): if `/courses` is called without `from`/`to`, the service returns courses in the `[now-10d, now+10d]` window.
- `SERVICE_AUTH_TOKEN`: shared token required for internal gRPC calls.
- `ATTENDANCE_GRPC_ADDR` (default `127.0.0.1:9093`): attendance gRPC address.
- `BEACON_GRPC_ADDR` (default `127.0.0.1:9094`): beacon gRPC address.
- `GRPC_DIAL_TIMEOUT` (default `5s`): timeout for gRPC dial.

## REST Endpoints (selected)
- `GET /schools`
- `POST /school`
- `GET /school/{schoolId}`
- `PATCH /school/{schoolId}`
- `DELETE /school/{schoolId}`
- `PATCH /school/{schoolId}/preferences`
- `GET /classrooms/{schoolId}`
- `POST /classroom`
- `GET /classroom/{classroomId}`
- `PATCH /classroom/{classroomId}`
- `DELETE /classroom/{classroomId}`
- `GET /courses`
- `POST /course`
- `GET /course/{courseId}`
- `PATCH /course/{courseId}`
- `DELETE /course/{courseId}`
- `POST /course/{courseId}/classrooms`
- `DELETE /course/{courseId}/classrooms/{classroomId}`
- `POST /course/{courseId}/studentGroups`
- `DELETE /course/{courseId}/studentGroup/{groupId}`
- `POST /course/{courseId}/teacher`
- `DELETE /course/{courseId}/teacher/{teacherId}`
- `GET /studentGroups/{schoolId}`
- `POST /studentGroup`
- `GET /studentGroup/{groupId}`
- `PATCH /studentGroup/{groupId}`
- `DELETE /studentGroup/{groupId}`
- `POST /studentGroup/{groupId}/students`
- `DELETE /studentGroup/{groupId}/student/{studentId}`

## gRPC
- `AcademicsQueryService.GetCourse`
- `AcademicsQueryService.ValidateTeacherCourse`
- `AcademicsQueryService.ValidateStudentCourse`
- `AcademicsQueryService.ValidateClassroomCourse`
- `AcademicsQueryService.GetSchoolPreferences`

Proto: `services/academics/academics/v1/academics.proto`
