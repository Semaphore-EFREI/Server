# Student Signature Challenge + Device Verification

This document defines the student-only challenge flow for `POST /signature` and the device verification headers required on all signature endpoints.

## Scope
- Applies to **students only**.
- Required on all endpoints under `/signature` and `/signatures`.
- Teachers/admins/devs are **exempt** (web use, no bound device).

## Cryptography & formats
- Algorithm: **ECDSA P-256** (ES256).
- Public key source: `auth-identity.student_devices.public_key` (PEM PKIX).
- Signature encoding: **base64 of ASN.1 DER** (`r`,`s`), recommended because it is widely supported and maps directly to Go `ecdsa.VerifyASN1`.

## Device verification headers (student requests)
Required on every student call to `/signature*` endpoints.

Headers:
- `X-Device-ID`: device identifier (must match the active student device).
- `X-Device-Timestamp`: Unix seconds.
- `X-Device-Signature`: base64 DER ECDSA signature.

Canonical message to sign:
```
method\npath\nstudentId\ndeviceId\ntimestamp\nbodySha256\nchallenge
```
- `method`: HTTP method (e.g., `POST`).
- `path`: request path (e.g., `/signature/123`).
- `studentId`: JWT `user_id`.
- `deviceId`: `X-Device-ID`.
- `timestamp`: `X-Device-Timestamp`.
- `bodySha256`: base64 of SHA-256 of the raw request body (empty body = hash of empty string).
- `challenge`: opaque nonce returned by the server (use empty string when no challenge is required).

Validation rules:
- Timestamp must be within a short window (±30s).
- Signature must verify with the active device public key.
- Device must be active and bound to the student.

## Challenge issuance (buzzLightyear / nfcCode)
Challenge is issued **only after** validating the beacon proof.

### BuzzLightyear (flash)
1) `GET /signature/buzzlightyear?beaconId=` returns a 28-bit code (short TTL, e.g., 15s).
2) Mobile flashes code to beacon.
3) `POST /signature/buzzlightyear/{beaconId}` with:
   - `courseId`
   - `signature` (beacon-signed proof of the 28-bit code)
4) On success, server returns a **challenge**.

### NFC (TOTP)
1) Beacon emits TOTP via NFC.
2) `POST /signature/nfcCode/{beaconId}` with:
   - `courseId`
   - `totpCode`
3) On success, server returns a **challenge**.

### Challenge payload
Server returns:
- `challenge` (opaque nonce, random)
- `expiresIn` (short TTL, 300s)

Server stores (Redis) with TTL and **single-use** (5 minutes):
- `challenge` (as the key)
- `courseId`
- `studentId`
- `deviceId`
- `method` (`buzzLightyear` or `nfc`) - **method-specific**
- `issuedAt`, `expiresAt`

## POST /signature (student)
Required fields (student):
- existing payload (`date`, `course`, `status`, `method`, `student`, etc.)
- `challenge` **only when** `method` is `buzzLightyear` or `nfc`
- device verification headers

Validation order:
1) JWT + role check (student).
2) Device signature verification (headers).
3) If method requires challenge (`buzzLightyear` or `nfc`), lookup:
   - exists, not expired, not used
   - `courseId`, `studentId`, `deviceId`, `method` match request
4) Standard attendance rules (course, timing, membership).
5) Consume challenge (delete key).

## Error codes (suggested)
- `device_signature_missing`, `device_signature_invalid`, `device_not_allowed`
- `challenge_missing`, `challenge_expired`, `challenge_used`, `challenge_mismatch`
- Existing signature errors remain unchanged.
