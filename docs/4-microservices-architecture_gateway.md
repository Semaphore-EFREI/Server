# Semaphore – API Gateway / Edge Architecture (Envoy)

This document is a **clean, implementation-ready specification** derived from the original project spec.
It is intended to be given directly to **Codex** to start implementation.

It focuses on:
- business rules
- access control
- core workflows
- non-functional constraints
- the 4-service architecture
- **API Gateway / Edge (Envoy) responsibilities** (public REST, internal gRPC)

For internal service contracts and gRPC specifics, see `docs/4-microservices-architecture-grpc.md`.

---

## 1. Project purpose

Semaphore is a **course attendance system** for schools and universities.

The server is the **core backbone** of the system:
- must be **always available**
- must not lose or corrupt attendance data
- must remain secure for all critical actions (authentication, attendance signing)

Attendance (signatures) is the **most critical domain** and must be implemented with extreme care.

---

## 2. User roles & separation of powers

The system has **three human roles**:

### 2.1 Student
- Can only access data related to:
  - their courses
  - their teachers
- Can only sign their **own attendance**
- Must register a **trusted device** before signing

### 2.2 Teacher
- Can access:
  - their courses
  - students enrolled in those courses
  - attendance records for those courses
- Can:
  - validate their own presence
  - open/close attendance signing
  - manually mark students present/absent

### 2.3 Administrator
- Has full access to **all data**
- Can configure the system (school preferences)
- Manages users, courses, classrooms, and assignments

---

## 3. Authentication & device security

### 3.1 Authentication model
- JWT-based authentication (can be evolved if needed)
- JWT is required for all protected endpoints
- JWT must include:
  - userId
  - userRole
  - schoolId

### 3.2 Student device binding (CRITICAL)
To prevent fraud (students signing for others):

1. When a student logs in on a device:
   - A **unique device identifier** is generated
   - It is sent to the server and linked to the student account
   - It is stored in the device secure enclave (iOS / Android)
   - It survives app uninstall

2. This device identifier is used to:
   - sign all **critical requests** (attendance signing)
   - reject signatures from unknown devices

3. Device change restriction:
   - A student can only change device **once per week** (or configurable)
   - Admin override may be allowed

Failure to comply must result in **signature rejection**.

---

## 4. Core data model (conceptual)

### 4.1 Users
- Base `User` entity
- Specialized roles:
  - Student
  - Teacher
  - Administrator

### 4.2 Academic structure
- School
- SchoolPreferences
- Classroom
- Course
- StudentGroup
- Relationships:
  - Teachers ↔ Courses
  - Students ↔ StudentGroups
  - Courses ↔ StudentGroups
  - Courses ↔ Classrooms

### 4.3 Attendance
- Signature
- StudentSignature
- TeacherSignature
- Each signature is linked to:
  - a course
  - a user
  - a timestamp
  - a status

### 4.4 Beacon (hardware)
- Beacon (classroom-bound device)
- Linked to a classroom
- Cryptographically authenticated

---

## 5. School preferences

SchoolPreferences define **global rules** for the system:
- default signature closing delay (minutes after course start)
- whether NFC / flashlight / QR signing is enabled
- whether students can sign before teacher presence
- other feature flags

Only administrators (or developers) can modify these preferences.

---

## 6. Functional requirements by role

### 6.1 Administration

Administrators must be able to:
- log in
- add / remove administrators
- add / modify / delete students and teachers
- add / modify / delete courses
- assign teachers to courses
- assign students (via groups) to courses
- assign classrooms to courses
- view attendance lists for any course
- modify school preferences

### 6.2 Teachers

Teachers must be able to:
- log in
- view their courses
- view attendance for their courses
- validate their own presence (course start)
- open / close student signing
- manually mark students present or absent
- receive notifications when a course starts

### 6.3 Students

Students must be able to:
- log in
- register a device
- view their courses
- sign their attendance
- receive notifications when signing opens

---

## 7. Attendance rules (core business logic)

Attendance rules MUST be enforced server-side.

### 7.1 Teacher presence
- A course is considered started only when:
  - the assigned teacher validates their presence
- Student signing may be blocked until teacher presence, depending on preferences

### 7.2 Time window
- Signing is allowed only:
  - between course start and end
  - within the configured closing delay
- Late signatures may be:
  - rejected
  - or marked as `LATE` (depending on policy)

### 7.3 Authorization
- Students can only sign:
  - for their own account
  - for courses they are enrolled in
- Teachers can only modify:
  - signatures of students in their courses
- Admins can modify any signature

### 7.4 Manual overrides
- Teachers and admins can manually set presence/absence
- Manual changes must be auditable

---

## 8. Beacon-based attendance (hardware)

### 8.1 Beacon purpose
Beacons are used to automate and secure attendance:
- classroom-bound hardware
- cryptographically authenticated
- linked to a classroom

### 8.2 Beacon security
- Each beacon has:
  - a public/private key pair
  - optional TOTP secret
- Beacon authentication is done via:
  - signed timestamps
  - short validity windows

### 8.3 Signing via beacon
1. Beacon authenticates itself to the server
2. Beacon emits a signing proof (e.g. flashlight / buzzLightyear)
3. Server validates proof (in beacon service)
4. Server creates a signature attempt (in attendance service)
5. Attendance service applies business rules

Beacons **never** write attendance directly.

---

## 9. Access restrictions (summary)

| Role | Access scope |
|----|----|
| Student | Own courses + own signatures |
| Teacher | Their courses + enrolled students |
| Admin | All data |
| Beacon | Only via beacon-specific endpoints |

---

## 10. Architecture: 4 microservices

### 10.1 auth-identity
- Human authentication (JWT + refresh)
- User CRUD (students/teachers/admins/devs)
- Role management
- **Student device registration & device-binding enforcement data**

### 10.2 academics
- Schools & preferences
- Courses, classrooms, student groups, memberships
- Assignments (teacher/group/classroom ↔ course)

### 10.3 attendance
- Signatures
- Attendance rules
- Status transitions
- Audit trail (who changed what, when, why)

### 10.4 beacon
- Beacon provisioning (dev/admin)
- Beacon authentication
- Proof verification (buzzLightyear / signed timestamp)
- Forwarding sign attempts to attendance

---

## 11. API Gateway / Edge (Envoy)

### 11.1 What the gateway is in this project
The API Gateway is the **single public entry point** for all clients (web/mobile/beacon).
It sits in front of the 4 services and provides **edge concerns** only.

In production, this gateway is expected to be **Envoy Gateway** (Gateway API-backed Envoy) or another edge proxy with equivalent features.

### 11.1.1 Envoy Gateway install (Helm)
Use the official Helm chart (latest at install time):

```
helm install eg oci://docker.io/envoyproxy/gateway-helm --version v0.0.0-latest -n envoy-gateway-system --create-namespace
```

Note: Gateway API CRDs must be present in the cluster. If the chart does not install them, install the standard CRDs separately before applying the gateway manifests.

If Istio mTLS is enabled:
- keep the Envoy Gateway control plane out of the mesh (disable injection on its pods)
- allow sidecar injection for data-plane pods (EnvoyProxy annotations already request injection)

Example values (control plane + certgen only):

```
deployment:
  pod:
    annotations:
      sidecar.istio.io/inject: "false"
certgen:
  job:
    pod:
      annotations:
        sidecar.istio.io/inject: "false"
```

### 11.2 Public API style
- **Public endpoints are HTTP REST (JSON)**.
- Services expose REST endpoints behind Envoy.
- Internal service-to-service communication is **gRPC only** (no REST between services).
  - gRPC contracts live in `docs/4-microservices-architecture-grpc.md`.

### 11.3 Gateway responsibilities (DO)
Envoy (gateway) must handle:
- TLS termination (HTTPS)
- Routing by path prefix to services
- JWT verification (signature/expiry) at the edge (recommended)
- Rate limiting (especially auth/signature/beacon endpoints)
- CORS
- Request ID / trace propagation
- Access logs + metrics

### 11.4 Gateway responsibilities (MUST NOT)
Envoy must **not** implement business rules:
- no attendance validation
- no “teacher presence” logic
- no database calls
- no cross-service orchestration

All business decisions remain inside domain services (attendance/academics/auth-identity/beacon).

### 11.5 Recommended routing table
Route by prefix (example):
- `/auth/*`, `/users/*` → auth-identity
- `/schools/*`, `/school/*`, `/courses/*`, `/classrooms/*`, `/groups/*` → academics
- `/signatures/*`, `/signature/*` → attendance
- `/beacon/*` → beacon

### 11.6 Retry policy (important)
- **Never retry non-idempotent writes** (e.g., create signature) at the gateway.
- Only allow retries for safe GET/read endpoints with tight timeouts.

---

## 12. Non-functional requirements

- No single point of failure (rolling updates without downtime)
- Attendance writes must be ACID
- Clear audit trail for all attendance changes
- Strict server-side validation
- Idempotency for critical operations
- Observability: logs, metrics, traces

---

## 13. Implementation priorities

1. Gateway (Envoy) skeleton routing + TLS + logging
2. Authentication & roles (auth-identity)
3. Academic structure (academics)
4. Attendance rules (attendance, manual first)
5. Student device binding end-to-end (auth-identity + attendance enforcement)
6. Beacon integration (beacon → attendance)
7. Notifications (future)

---

End of specification.
