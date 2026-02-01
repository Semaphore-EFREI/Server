# 4-Microservice Architecture (gRPC internal)

This document defines the **initial 4 microservices** for the project and how they interact using **gRPC internally**.
It is designed to be handed to an implementation agent (Codex) to start building the system.

---

## Services

1. **auth-identity**  
   Human authentication + user management (students/teachers/admins/devs).

2. **academics**  
   School structure + planning: schools/preferences, classrooms, student groups & memberships, courses & assignments.

3. **attendance**  
   Attendance truth: signatures (student/teacher/admin), rules, status transitions, audit.

4. **beacon**  
   Hardware-facing service: beacon provisioning, beacon authentication, buzzLightyear/flashlight proof verification, beacon telemetry.

---

## Non-negotiable principles

### 1) Data ownership
Each service owns its data (its tables). No cross-service joins, no shared tables.

### 2) References by ID only
Services reference external entities by UUID only (e.g., `course_id`, `student_id`, `school_id`).

### 3) Internal communication via gRPC
All service-to-service calls are gRPC. Public APIs are REST (JSON) via the Envoy API Gateway.

### 4) Authorization: JWT everywhere (humans), service identity for internal calls
- Human requests use **JWT** issued by auth-identity.
- Internal gRPC calls should use **mTLS** and/or a signed service JWT, plus `x-request-id` propagation.

---

## High-level dependency graph

- Public clients → **Envoy API Gateway** → (REST) → services
- **attendance** → gRPC → **academics** (validation)
- **beacon** → gRPC → **attendance** (submit verified sign attempts)
- Optional (rare): **academics** → gRPC → **auth-identity** (user display lookups)

---

## Database ownership (tables/entities)

| Entity / Table | Owner | Notes |
|---|---|---|
| `User` | auth-identity | profile + identity fields |
| `Student`, `Teacher`, `Administrator`, `Developer` | auth-identity | role subtype tables |
| `RefreshTokenSession` (recommended) | auth-identity | refresh token tracking/revocation |
| `School`, `SchoolPreferences` | academics | includes feature flags + default signature closing delay |
| `Classroom` | academics | belongs to a school |
| `StudentGroup`, `StudentsGroups` | academics | groups + membership |
| `Course` | academics | start/end, online, signature settings |
| `TeachersCourses`, `CoursesClassrooms`, `CoursesStudentGroups` | academics | association tables |
| `Signature`, `StudentSignature`, `TeacherSignature` | attendance | attendance truth + audit |
| `Beacon` | beacon | keys, assignment to classroom, version |

---

## Authentication & Authorization model

### JWT claims (recommended minimum)
Issued by **auth-identity** and consumed by other services:
- `sub`: user UUID
- `user_type`: `student | teacher | admin | dev`
- `school_id`: UUID
- `admin_role`: optional (enum/flags)

### Authorization rules: where they live
- **auth-identity**: authentication + user CRUD permissions
- **academics**: school/classroom/group/course CRUD permissions
- **attendance**: signature access rules and state transitions (source of truth)
- **beacon**: beacon provisioning + beacon auth; does **not** decide attendance status logic

---

## Internal gRPC APIs (contracts)

Below are the internal gRPC contracts required for the 4-service split.
They are minimal, stable, and designed to avoid tight coupling.

> Naming convention: `package <domain>.<service>.v1`  
> Prefer: `uuid` as string (canonical UUID) at proto level.  
> Timestamps: `google.protobuf.Timestamp`.

---

# 1) academics gRPC (consumed by attendance)

**Goal:** attendance needs to validate relationships for a course:  
- course exists and belongs to a school  
- teacher is assigned to course  
- student is in a group assigned to course  
- classroom belongs to course (optional)

## Proto: `academics.proto`

```proto
syntax = "proto3";

package academics.api.v1;

import "google/protobuf/timestamp.proto";

message Course {
  string id = 1;
  string school_id = 2;
  string name = 3;
  google.protobuf.Timestamp start_at = 4;
  google.protobuf.Timestamp end_at = 5;
  bool is_online = 6;

  // attendance-related configuration (derived from school prefs or overridden per course)
  int32 signature_closing_delay_minutes = 7; // minutes after start when signing closes
  bool signature_closed = 8;
}

message GetCourseRequest { string course_id = 1; }
message GetCourseResponse { Course course = 1; }

message ValidateTeacherCourseRequest {
  string teacher_id = 1;
  string course_id = 2;
}
message ValidateTeacherCourseResponse { bool is_assigned = 1; }

message ValidateStudentCourseRequest {
  string student_id = 1;
  string course_id = 2;
}
message ValidateStudentCourseResponse {
  bool is_allowed = 1;
  // Optional info for debugging/audit
  repeated string matched_group_ids = 2;
}

message ValidateClassroomCourseRequest {
  string classroom_id = 1;
  string course_id = 2;
}
message ValidateClassroomCourseResponse { bool is_linked = 1; }

message SchoolPreferences {
  string id = 1;
  int32 default_signature_closing_delay_minutes = 2;
  bool teacher_can_modify_closing_delay = 3;
  bool students_can_sign_before_teacher = 4;
  bool enable_flash = 5;
  bool disable_course_modification_from_ui = 6;
  bool enable_nfc = 7;
}

message GetSchoolPreferencesRequest { string school_id = 1; }
message GetSchoolPreferencesResponse { SchoolPreferences preferences = 1; }

message CloseExpiredCoursesRequest {
  google.protobuf.Timestamp now = 1;
}

message CloseExpiredCoursesResponse {
  int64 closed_count = 1;
}

service AcademicsQueryService {
  rpc GetCourse(GetCourseRequest) returns (GetCourseResponse);

  rpc ValidateTeacherCourse(ValidateTeacherCourseRequest)
    returns (ValidateTeacherCourseResponse);

  rpc ValidateStudentCourse(ValidateStudentCourseRequest)
    returns (ValidateStudentCourseResponse);

  rpc ValidateClassroomCourse(ValidateClassroomCourseRequest)
    returns (ValidateClassroomCourseResponse);

  rpc GetSchoolPreferences(GetSchoolPreferencesRequest)
    returns (GetSchoolPreferencesResponse);
}

service AcademicsCommandService {
  rpc CloseExpiredCourses(CloseExpiredCoursesRequest)
    returns (CloseExpiredCoursesResponse);
}
```

### Notes
- `GetCourse` is used to enforce **same school** and time window rules.
- `ValidateStudentCourse` should check student membership in **any** group assigned to the course.
- These are **read-only** query endpoints (idempotent).
- `CloseExpiredCourses` is a **command** endpoint used by attendance’s signature close job.

---

# 2) attendance gRPC (consumed by beacon)

**Goal:** beacon verifies cryptographic proof / sensor proof and sends a sign attempt to attendance.
Attendance decides the final business result and persists it.

## Proto: `attendance.proto`

```proto
syntax = "proto3";

package attendance.api.v1;

import "google/protobuf/timestamp.proto";

enum SignatureMethod {
  SIGNATURE_METHOD_UNSPECIFIED = 0;
  SIGNATURE_METHOD_QR = 1;
  SIGNATURE_METHOD_NFC = 2;
  SIGNATURE_METHOD_FLASHLIGHT = 3;     // buzzLightyear-style
  SIGNATURE_METHOD_BEACON = 4;         // generic beacon presence
  SIGNATURE_METHOD_TEACHER = 5;        // teacher marked attendance
  SIGNATURE_METHOD_ADMIN = 6;          // admin override
}

enum SignatureStatus {
  SIGNATURE_STATUS_UNSPECIFIED = 0;
  SIGNATURE_STATUS_PENDING = 1;
  SIGNATURE_STATUS_ACCEPTED = 2;
  SIGNATURE_STATUS_REFUSED = 3;
  SIGNATURE_STATUS_LATE = 4;
}

message BeaconProof {
  // Beacon-provided details AFTER beacon service validation.
  string beacon_id = 1;
  string classroom_id = 2;
  string proof_type = 3;         // "buzzLightyear", "signedTimestamp", etc.
  bytes proof_payload = 4;       // opaque blob
  google.protobuf.Timestamp proof_time = 5;
}

message CreateSignatureAttemptRequest {
  // Target course (optional if attendance can resolve from classroom + time)
  string course_id = 1;

  // The user who is signing (student_id in most cases)
  string student_id = 2;

  // Method used; beacon service typically sets FLASHLIGHT/BEACON
  SignatureMethod method = 3;

  // Optional contextual teacher/admin references if needed later
  string teacher_id = 4;
  string administrator_id = 5;

  // Proof provided by beacon service
  BeaconProof beacon_proof = 6;

  // Request time from beacon service
  google.protobuf.Timestamp received_at = 7;
}

message CreateSignatureAttemptResponse {
  string signature_id = 1;
  SignatureStatus status = 2;
  string message = 3; // human-readable reason if refused, late, etc.
}

service AttendanceCommandService {
  rpc CreateSignatureAttempt(CreateSignatureAttemptRequest)
    returns (CreateSignatureAttemptResponse);
}
```

### Notes
- Attendance is the only service that creates `Signature` rows.
- Beacon service performs cryptographic verification; attendance performs business validation.

---

# 3) auth-identity gRPC (optional, minimized)

**Goal:** avoid needing identity lookups for every request (use JWT claims).
Keep gRPC endpoints for rare use-cases: display names, existence checks.

## Proto: `identity.proto`

```proto
syntax = "proto3";

package identity.api.v1;

message UserLite {
  string id = 1;
  string school_id = 2;
  string email = 3;
  string firstname = 4;
  string lastname = 5;
  string user_type = 6; // student/teacher/admin/dev
}

message GetUserLiteRequest { string user_id = 1; }
message GetUserLiteResponse { UserLite user = 1; }

message ExistsRequest { string user_id = 1; }
message ExistsResponse { bool exists = 1; }

message ValidateStudentDeviceRequest {
  string student_id = 1;
  string device_identifier = 2;
}
message ValidateStudentDeviceResponse { bool is_valid = 1; }

service IdentityQueryService {
  rpc GetUserLite(GetUserLiteRequest) returns (GetUserLiteResponse);
  rpc Exists(ExistsRequest) returns (ExistsResponse);
  rpc ValidateStudentDevice(ValidateStudentDeviceRequest)
    returns (ValidateStudentDeviceResponse);
}
```

---

# 4) beacon internal model

Beacon service owns beacon authentication and verification, so other services never touch private keys/totp secrets.

### Beacon responsibilities
- Maintain beacon keys (`signature_key` = public key, `totp_key`)
- Authenticate beacons (signed timestamp)
- Validate buzzLightyear proof payload
- Resolve assigned `classroom_id` for beacon
- Submit verified attempts to attendance via gRPC

---

## Inter-service flow definitions

### Flow A — Student signs via beacon (buzzLightyear/flashlight)
1) Beacon → beacon: authenticate (`beacon/auth/token`) using signed timestamp
2) Beacon → beacon: submit buzzLightyear proof
3) Beacon:
   - verifies the signature/proof
   - resolves `classroom_id` from its DB
   - identifies candidate `course_id` (optional; can be resolved by attendance if it has a mapping)
4) Beacon → attendance (gRPC): `CreateSignatureAttempt`
5) Attendance:
   - calls academics via gRPC (`GetCourse`, `ValidateStudentCourse`, and optionally `ValidateClassroomCourse`)
   - applies time-window rules, closing delay rules
   - writes Signature rows
   - returns status

### Flow B — Student signs directly (QR/NFC)
1) Client → attendance (public API)
2) Attendance:
   - calls academics to validate membership / teacher assignment as needed
   - writes signature record

---

## Attendance validation rules (starter set)

Attendance should enforce at least:

1) **Course exists** and course belongs to same `school_id` as user token.
2) **Course time window**: now between `start_at` and `end_at` (or within allowed grace).
3) **Signature closing delay**: `now <= start_at + signature_closing_delay_minutes`.
4) **Student membership**: student belongs to at least one group assigned to course.
5) **Teacher assignment** (for teacher actions): teacher is assigned to course.
6) **Patch restrictions**: only certain roles can patch `status` or attach administrator fields.

Start with strict checks and log the rejection reason for audit.

---

## Public API routing (Envoy gateway)

Envoy exposes REST endpoints for each service and routes by prefix to the owning microservice.
Gateway responsibilities and edge concerns are defined in `docs/4-microservices-architecture_gateway.md`.

Route by prefix:

- `/auth/*`, `/users/*` → auth-identity
- `/schools/*`, `/school/*`, `/courses/*`, `/classrooms/*`, `/groups/*` → academics
- `/signatures/*`, `/signature/*` → attendance
- `/beacon/*`, `/dev/beacon*` → beacon

---

## Deployment & ops (minimal but production-friendly)

### Service template (Go)
Each service includes:
- gRPC server + health check
- HTTP server for REST endpoints behind Envoy
- Postgres client + migrations
- Structured logs + request id propagation
- OpenTelemetry tracing (recommended)

### gRPC hard requirements
- Deadline propagation (timeouts)
- Retries only for idempotent queries (academics query calls)
- mTLS between services (or service JWT)
- Per-request `x-request-id` / trace id propagation

### Redis usage (optional at this stage)
- Cache results in attendance:
  - `ValidateStudentCourse(student_id, course_id)`
  - `GetCourse(course_id)`
- Later: Redis Streams for async events (analytics/notifications), not required now.

---

## Implementation checklist

### auth-identity
- [ ] DB schema: users + role subtype tables + refresh sessions
- [ ] REST endpoints for login/refresh + CRUD users
- [ ] JWT issuing + verification middleware
- [ ] (Optional) gRPC IdentityQueryService

### academics
- [x] DB schema: school/prefs, classrooms, groups/membership, courses, link tables
- [x] REST endpoints for all academics features
- [x] gRPC AcademicsQueryService (GetCourse + Validate*)
- [x] gRPC AcademicsCommandService (CloseExpiredCourses)
- [x] Consistent `school_id` checks for admin operations

### attendance
- [x] DB schema: signature + studentSignature + teacherSignature
- [x] REST endpoints for signature CRUD/patch
- [x] gRPC AttendanceCommandService (CreateSignatureAttempt)
- [x] Calls academics gRPC for validation (start with runtime checks)
- [ ] Clear rejection reasons and audit log fields

### beacon
- [ ] DB schema: beacons (keys, classroom assignment, version)
- [ ] REST endpoints for beacon auth + management + buzzLightyear
- [ ] Cryptographic verification (ECDSA signed timestamp, etc.)
- [ ] gRPC client to attendance CreateSignatureAttempt

---

## Versioning strategy

- gRPC: `...api.v1` packages, add fields only (backward compatible)
- REST: keep versioning optional (`/v1/...`) or gateway-level
- DB: migrations per service; never coordinated cross-service migrations

---

## Appendix: shared proto conventions

- UUIDs are `string` (canonical format)
- Use `google.protobuf.Timestamp` for times
- Enums use `UNSPECIFIED = 0`
- Keep messages stable; only add new fields at the end

---

End of document.
