# Planning Update: Swagger vs Services Alignment

Last updated: 2026-01-30

## Scope
Align the implementation with the current Swagger (`docs/openapi_v3.json`) and the corrections list (`docs/correction_api.md`) across:
- `services/auth-identity`
- `services/academics`
- `services/attendance`
- `services/beacon`
- `migrations/academics`

## Summary of Required Changes

### Auth / Identity
- Token field naming: use `accessToken` and `refreshToken` (camelCase) in responses and requests.
- `/auth/refresh`: Swagger lists `userId` and `userType`, server currently accepts only `refreshToken`.
- `/auth/logout`: server expects `refreshToken` body; Swagger defines no request body.
- Admin roles: code only accepts `super_admin` and `school_admin`; Swagger values are inconsistent.

### Academics
- `GET /courses`: admin/dev should be able to fetch all school courses without `userId`.
- `Course` response missing `endDate` (Swagger requires it).
- `CourseExtended`: support `students`, `soloStudents`, `studentGroups` in GET `/courses` and `/course/{courseId}`.
- `POST /course`: accept optional `classroomsId`, `teachersId`, `studentsId`, `studentGroupsId`.
- Add endpoints:
  - `POST /course/{courseId}/students`
  - `DELETE /course/{courseId}/student/{studentId}`
- `POST /classroom`: support optional list of beacon IDs.
- School preferences: add `disableCourseModificationFromUI`, remove `qrCodeEnabled` in API and DB.
- School response shape: Swagger `School.preferences` is a UUID, but code returns a nested object when expanded.

### Attendance / Signatures
- `POST /signature`: image must be optional for teacher signatures.
- Allow admin/teacher to mark a student present without a device challenge.
- `administrator` should be optional in teacher signature payload.

### Beacon
- Add admin-accessible `/beacons` to list beacons of admin school and `/beacon/{beaconId}` (non-dev paths) scoped to their school.
- Swagger does not list beacon auth endpoints (`/beacon/auth/token`, `/beacon/auth/refreshToken`). No auth is required for beacons.
- Swagger defines `POST /signature/buzzlightyear/{beaconId}`; code uses `POST /beacon/buzzLightyear`.

### Swagger Fixups
- `/auth/login` request lists `userType` as required but property is missing.
- `TokenGroup` uses `accesToken` typo; also mixes `token` vs `accessToken` naming.

## Decisions
- Auth token schema: confirm canonical fields (`accessToken`/`refreshToken`) and update both spec + code.
- `/auth/refresh`: keep minimal payload and remove `userId`; remove `userType` from schema.
- `/auth/logout`: bearer-only logout.
- School response: keep nested preferences if include arg and expose `preferencesId` in all case in `School`.
- Buzzlightyear path: change to `POST /signature/buzzlightyear/{beaconId}` with correct beaconId. Add beacon id link into redis cache key.

## Implementation Plan (proposed)
1. **Auth schema alignment**
   - Update DTOs in `services/auth-identity/internal/http/server.go`.
   - Update Swagger token schema + auth request bodies.
2. **Academics course models**
   - Add `endDate` in course response mapping.
   - Extend GET includes to load students/soloStudents/studentGroups.
   - Accept optional IDs in `POST /course` and wire associations.
   - Add `/course/{courseId}/students` and delete route.
3. **Classroom + beacons**
   - Add beacon list in `POST /classroom` and store associations.
4. **School preferences**
   - Update `SchoolPreferences` API and handlers.
   - Add DB migration for `disable_course_modification_from_ui`; remove `enable_qrcode` if deprecated.
5. **Attendance signature flows**
   - Relax teacher image requirement.
   - Allow admin/teacher manual presence for students.
   - Make `administrator` optional.
6. **Beacon API**
   - Add admin endpoints and update Swagger.
   - Resolve buzzlightyear endpoint mismatch.

## Files Likely to Change
- `docs/openapi_v3.json`
- `docs/correction_api.md` (if updating resolved items)
- `services/auth-identity/internal/http/server.go`
- `services/academics/internal/http/server.go`
- `services/attendance/internal/http/server.go`
- `services/beacon/internal/http/server.go`
- `migrations/academics/*`
- `docs/database-schema.md` (if DB changes are accepted)

## Test Notes
- No formal test harness yet. For each service, run:
  - `go test ./...`
- Manual spot-checks needed for all modified endpoints.
