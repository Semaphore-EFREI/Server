
## TODO
1. [P1] Implement cascade delete of student signatures and devices when a student is deleted in auth-identity.
2. [P2] Finalize and document the beacon gRPC → attendance integration flow.
3. [P1] Add unit and integration tests to improve coverage in all services.
4. [P1] Implement missing attendance rules: teacher presence gating, school preference method enforcement, open/close signing endpoints.
5. [P1] Validate `teacher_id`/`administrator_id` in gRPC CreateSignatureAttempt when provided (avoid silent NULLs).
6. [P2] Distinguish DB errors vs authorization in academics `handleGetCourse` student/teacher checks.
7. [P0] Enforce admin school scoping in auth-identity for student/teacher/admin list and create endpoints.
8. [P2] Add pagination to `ListCourseSignatures` gRPC query (hard limit 500 today).
9. [P3] Handle `UpdateDeviceLastSeen` errors in identity gRPC (log or propagate).
10. [P2] Student can actually post signature with signed status and image omitted when it should be required
11. [P1] Closing signatures job should happen at end of the course and not after signature delay used for late signings.

## TODO - FRONTEND
1. [P1] Correct interceptor on token expiry to use refresh token flow.
2. [P0] Correct image asset for fast loading
