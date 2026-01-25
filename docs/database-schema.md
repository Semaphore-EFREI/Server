# Database Schema (Per-Service)

This repository uses **one Postgres database per microservice**. Each service owns its tables and only stores **UUID references** to external entities (no cross-service foreign keys). Referential checks are enforced via internal gRPC calls.

## Auth-Identity DB
Tables:
- `users`: core identity data (email, password hash, school_id, names, timestamps).
- `students`, `teachers`, `administrators`, `developers`: role tables keyed by `user_id`.
- `refresh_token_sessions`: session/refresh token tracking.
- `student_devices`: device binding for student authentication.

Device binding lives in **auth-identity** (source of truth). Attendance validates device identifiers through auth-identity (gRPC) or a short-lived cache.

## Academics DB
Tables:
- `school_preferences`, `schools`.
- `classrooms`, `courses`.
- `student_groups`, `students_groups` (student membership).
- `teachers_courses`, `courses_student_groups`, `courses_classrooms`.

All student/teacher references are UUIDs from auth-identity with **no FK constraints**.

## Attendance DB
Tables:
- `signatures`: base attendance events (course_id, signed_at, status, method).
- `student_signatures`: links a signature to a student; may include `teacher_id` or `administrator_id` when manual overrides occur.
- `teacher_signatures`: links a signature to a teacher (presence validation).

## Beacon DB
Tables:
- `beacons`: hardware metadata, keys, optional classroom assignment, and telemetry timestamps.

## Enums
- `signature_method`: `flash`, `qrcode`, `nfc`.
- `signature_status`: `present`, `absent`, `late`, `excused`, `invalid`.
- `admin_role`: `super_admin`, `school_admin`.

## Constraints & Indexing (Highlights)
- Unique: `users.email`, `beacons.serial_number`, device identifiers.
- Join tables enforce uniqueness on pairs (e.g., `teachers_courses(teacher_id, course_id)`).
- Timestamps are stored as **UTC** (`timestamptz` recommended).

## ChartDB Export
The per-service schema is available at `docs/ChartDB_per_service.json`.
