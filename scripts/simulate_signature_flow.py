#!/usr/bin/env python3
import argparse
import base64
import datetime as dt
import email.utils
import hashlib
import hmac
import json
import os
import random
import sys
import time
import uuid

try:
    import requests
except ImportError as exc:
    raise SystemExit(
        "Missing dependency: requests. Install with: pip install requests") from exc

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.cmac import CMAC
    from cryptography.hazmat.primitives.ciphers import algorithms
except ImportError as exc:
    raise SystemExit(
        "Missing dependency: cryptography. Install with: pip install cryptography") from exc


DEFAULT_STATE_FILE = "signature_flow_state.json"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Simulate student signature flows (buzzlightyear + NFC).")
    parser.add_argument(
        "--base-url", default=os.getenv("SEMAPHORE_BASE_URL", "").strip(), help="Base API URL")
    parser.add_argument("--admin-email", default=os.getenv(
        "SEMAPHORE_ADMIN_EMAIL", "").strip(), help="Admin email")
    parser.add_argument("--admin-password", default=os.getenv(
        "SEMAPHORE_ADMIN_PASSWORD", "").strip(), help="Admin password")
    parser.add_argument("--dev-email", default=os.getenv("SEMAPHORE_DEV_EMAIL",
                        "").strip(), help="Dev email (for beacon creation)")
    parser.add_argument("--dev-password", default=os.getenv(
        "SEMAPHORE_DEV_PASSWORD", "").strip(), help="Dev password")
    parser.add_argument("--seed", default="",
                        help="Seed string for naming and cleanup")
    parser.add_argument(
        "--state-file", default=DEFAULT_STATE_FILE, help="State file path")
    parser.add_argument("--cleanup", action="store_true",
                        help="Cleanup resources from a previous run")
    return parser.parse_args()


def require(value, name):
    if not value:
        raise SystemExit(f"Missing required value: {name}")


def request_json(method, url, token=None, body=None, headers=None):
    headers = headers or {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        headers["Content-Type"] = "application/json"
        resp = requests.request(
            method, url, headers=headers, data=json.dumps(body).encode("utf-8"))
    else:
        resp = requests.request(method, url, headers=headers)
    if resp.status_code >= 400:
        raise RuntimeError(
            f"{method} {url} failed ({resp.status_code}): {resp.text}")
    if resp.text:
        return resp.json()
    return None


def request_with_response(method, url, token=None, body=None, headers=None):
    headers = headers or {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        headers["Content-Type"] = "application/json"
        resp = requests.request(
            method, url, headers=headers, data=json.dumps(body).encode("utf-8"))
    else:
        resp = requests.request(method, url, headers=headers)
    return resp


def login(base_url, email, password):
    payload = {"email": email, "password": password}
    data = request_json("POST", f"{base_url}/auth/login", body=payload)
    return data["accessToken"]


def get_me(base_url, token):
    return request_json("GET", f"{base_url}/auth/me", token=token)


def get_server_time(base_url, token):
    resp = request_with_response("GET", f"{base_url}/auth/me", token=token)
    date_header = resp.headers.get("Date")
    if not date_header:
        return dt.datetime.now(dt.timezone.utc)
    server_time = email.utils.parsedate_to_datetime(date_header)
    if server_time.tzinfo is None:
        server_time = server_time.replace(tzinfo=dt.timezone.utc)
    else:
        server_time = server_time.astimezone(dt.timezone.utc)
    return server_time


def sha256_b64(data):
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


def device_signature_message(method, path, student_id, device_id, timestamp, body_hash, challenge):
    return "\n".join([method, path, student_id, device_id, str(timestamp), body_hash, challenge])


class DeviceSigner:
    def __init__(self, student_id, device_id, private_key):
        self.student_id = student_id
        self.device_id = device_id
        self.private_key = private_key

    def public_key_pem(self):
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    def sign_headers(self, method, path, body_bytes, challenge=""):
        timestamp = int(time.time())
        print(f"Signing request at timestamp: {timestamp}")
        print(f"Request body bytes: {body_bytes}")
        body_hash = sha256_b64(body_bytes)
        message = device_signature_message(
            method, path, self.student_id, self.device_id, timestamp, body_hash, challenge
        )
        print(f"Signing message:\n'{message}'\n")
        signature = self.private_key.sign(
            message.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        return {
            "X-Device-ID": self.device_id,
            "X-Device-Timestamp": str(timestamp),
            "X-Device-Signature": base64.b64encode(signature).decode("ascii"),
        }


def request_with_device(method, base_url, path, token, signer, body=None):
    body_bytes = b""
    if body is not None:
        body_bytes = json.dumps(body, separators=(
            ",", ":"), ensure_ascii=False).encode("utf-8")
    signature_path = path.split("?", 1)[0]
    challenge = ""
    if method.upper() == "POST" and signature_path == "/signature" and body is not None:
        challenge = body.get("challenge", "") or ""
    headers = signer.sign_headers(
        method.upper(), signature_path, body_bytes, challenge=challenge)
    headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        headers["Content-Type"] = "application/json"
    url = f"{base_url}{path}"
    resp = requests.request(method, url, headers=headers,
                            data=body_bytes if body is not None else None)
    if resp.status_code >= 400:
        raise RuntimeError(
            f"{method} {url} failed ({resp.status_code}): {resp.text}")
    if resp.text:
        return resp.json()
    return None


def request_with_device_response(method, base_url, path, token, signer, body=None):
    body_bytes = b""
    if body is not None:
        body_bytes = json.dumps(body, separators=(
            ",", ":"), ensure_ascii=False).encode("utf-8")
    signature_path = path.split("?", 1)[0]
    challenge = ""
    if method.upper() == "POST" and signature_path == "/signature" and body is not None:
        challenge = body.get("challenge", "") or ""
    headers = signer.sign_headers(
        method.upper(), signature_path, body_bytes, challenge=challenge)
    headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        headers["Content-Type"] = "application/json"
    url = f"{base_url}{path}"
    return requests.request(method, url, headers=headers, data=body_bytes if body is not None else None)


def request_with_custom_headers(method, base_url, path, token, headers=None, body=None):
    headers = dict(headers or {})
    headers["Authorization"] = f"Bearer {token}"
    body_bytes = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        body_bytes = json.dumps(body, separators=(
            ",", ":"), ensure_ascii=False).encode("utf-8")
    url = f"{base_url}{path}"
    return requests.request(method, url, headers=headers, data=body_bytes)


def expect_error(resp, expected_code):
    if resp.status_code < 400:
        raise RuntimeError(
            f"Expected error {expected_code}, got {resp.status_code}: {resp.text}")
    try:
        payload = resp.json()
    except ValueError:
        payload = {}
    actual = payload.get("error")
    if expected_code and actual != expected_code:
        raise RuntimeError(
            f"Expected error {expected_code}, got {actual} ({resp.status_code}): {resp.text}")
    print(f"Negative test ok: {expected_code} ({resp.status_code})")


def totp(secret_bytes, timestamp, step=30, digits=6):
    counter = int(timestamp // step)
    msg = counter.to_bytes(8, "big")
    digest = hmac.new(secret_bytes, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (
        ((digest[offset] & 0x7F) << 24)
        | ((digest[offset + 1] & 0xFF) << 16)
        | ((digest[offset + 2] & 0xFF) << 8)
        | (digest[offset + 3] & 0xFF)
    )
    return str(code % (10 ** digits)).zfill(digits)


def now_unix():
    return int(time.time())


def random_base64_secret(byte_len=20):
    raw = os.urandom(byte_len)
    return base64.b64encode(raw).decode("ascii"), raw


def build_state(seed):
    return {
        "seed": seed,
        "created": {
            "users": {},
            "classroom_id": None,
            "student_group_id": None,
            "course_id": None,
            "extra_course_id": None,
            "beacon_id": None,
            "signatures": [],
        },
        "totp_secret_b64": None,
    }


def save_state(path, state):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)


def load_state(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def create_user(base_url, admin_token, school_id, email, user_type, first_name, last_name, password, student_number=None):
    payload = {
        "email": email,
        "password": password,
        "firstName": first_name,
        "lastName": last_name,
        "schoolId": school_id,
        "userType": user_type,
    }
    if student_number:
        payload["studentNumber"] = student_number
    return request_json("POST", f"{base_url}/users", token=admin_token, body=payload)


def main():
    args = parse_args()
    require(args.base_url, "base URL (--base-url or SEMAPHORE_BASE_URL)")
    require(args.admin_email, "admin email (--admin-email or SEMAPHORE_ADMIN_EMAIL)")
    require(args.admin_password,
            "admin password (--admin-password or SEMAPHORE_ADMIN_PASSWORD)")
    require(args.dev_email, "dev email (--dev-email or SEMAPHORE_DEV_EMAIL)")
    require(args.dev_password,
            "dev password (--dev-password or SEMAPHORE_DEV_PASSWORD)")

    if args.cleanup:
        state = load_state(args.state_file)
        admin_token = login(args.base_url, args.admin_email,
                            args.admin_password)
        dev_token = login(args.base_url, args.dev_email, args.dev_password)

        for sig_id in state["created"].get("signatures", []):
            request_json(
                "DELETE", f"{args.base_url}/signature/{sig_id}", token=admin_token)

        course_id = state["created"].get("course_id")
        if course_id:
            request_json(
                "DELETE", f"{args.base_url}/course/{course_id}", token=admin_token)

        extra_course_id = state["created"].get("extra_course_id")
        if extra_course_id:
            request_json(
                "DELETE", f"{args.base_url}/course/{extra_course_id}", token=admin_token)

        group_id = state["created"].get("student_group_id")
        if group_id:
            request_json(
                "DELETE", f"{args.base_url}/studentGroup/{group_id}", token=admin_token)

        classroom_id = state["created"].get("classroom_id")
        if classroom_id:
            request_json(
                "DELETE", f"{args.base_url}/classroom/{classroom_id}", token=admin_token)

        beacon_id = state["created"].get("beacon_id")
        if beacon_id:
            request_json(
                "DELETE", f"{args.base_url}/beacon/{beacon_id}", token=dev_token)

        for user_id in state["created"]["users"].values():
            request_json(
                "DELETE", f"{args.base_url}/users/{user_id}", token=admin_token)

        print("Cleanup complete.")
        return

    seed = args.seed or uuid.uuid4().hex[:10]
    state = build_state(seed)

    admin_token = login(args.base_url, args.admin_email, args.admin_password)
    dev_token = login(args.base_url, args.dev_email, args.dev_password)
    admin_me = get_me(args.base_url, admin_token)
    school_id = admin_me["schoolId"]

    school = request_json(
        "GET",
        f"{args.base_url}/school/{school_id}?expand=preferences",
        token=admin_token,
    )
    prefs = school.get("preferences")
    if prefs:
        prefs["flashlightEnabled"] = True
        prefs["nfcEnabled"] = True
        request_json(
            "PATCH",
            f"{args.base_url}/school/{school_id}/preferences",
            token=admin_token,
            body=prefs,
        )

    student_password = f"pw-{seed}"
    teacher_password = f"pw-{seed}"

    teacher = create_user(
        args.base_url,
        admin_token,
        school_id,
        f"teacher-{seed}@example.com",
        "teacher",
        "Prof",
        f"Seed{seed}",
        teacher_password,
    )
    state["created"]["users"]["teacher"] = teacher["id"]

    students = []
    for i in range(1, 4):
        student = create_user(
            args.base_url,
            admin_token,
            school_id,
            f"student-{seed}-{i}@example.com",
            "student",
            "Student",
            f"Seed{seed}{i}",
            student_password,
            student_number=f"{seed}{i:02d}",
        )
        state["created"]["users"][f"student_{i}"] = student["id"]
        students.append(student)

    classroom = request_json(
        "POST",
        f"{args.base_url}/classroom",
        token=admin_token,
        body={"name": f"Room-{seed}"},
    )
    state["created"]["classroom_id"] = classroom["id"]

    student_group = request_json(
        "POST",
        f"{args.base_url}/studentGroup",
        token=admin_token,
        body={"name": f"Group-{seed}", "singleStudentGroup": False},
    )
    state["created"]["student_group_id"] = student_group["id"]

    request_json(
        "POST",
        f"{args.base_url}/studentGroup/{student_group['id']}/students",
        token=admin_token,
        body={"studentsIds": [s["id"] for s in students]},
    )

    start = now_unix() - 60
    end = now_unix() + 3600
    course = request_json(
        "POST",
        f"{args.base_url}/course",
        token=admin_token,
        body={
            "name": f"Course-{seed}",
            "date": start,
            "endDate": end,
            "isOnline": False,
        },
    )
    state["created"]["course_id"] = course["id"]

    request_json(
        "POST",
        f"{args.base_url}/course/{course['id']}/classrooms",
        token=admin_token,
        body={"classroomId": classroom["id"]},
    )
    request_json(
        "POST",
        f"{args.base_url}/course/{course['id']}/studentGroups",
        token=admin_token,
        body={"groupsIds": [student_group["id"]]},
    )
    request_json(
        "POST",
        f"{args.base_url}/course/{course['id']}/teacher",
        token=admin_token,
        body={"teacherId": teacher["id"]},
    )

    extra_course = request_json(
        "POST",
        f"{args.base_url}/course",
        token=admin_token,
        body={
            "name": f"Course-{seed}-extra",
            "date": start,
            "endDate": end,
            "isOnline": False,
        },
    )
    state["created"]["extra_course_id"] = extra_course["id"]
    request_json(
        "POST",
        f"{args.base_url}/course/{extra_course['id']}/classrooms",
        token=admin_token,
        body={"classroomId": classroom["id"]},
    )
    request_json(
        "POST",
        f"{args.base_url}/course/{extra_course['id']}/studentGroups",
        token=admin_token,
        body={"groupsIds": [student_group["id"]]},
    )
    request_json(
        "POST",
        f"{args.base_url}/course/{extra_course['id']}/teacher",
        token=admin_token,
        body={"teacherId": teacher["id"]},
    )

    totp_secret_b64, totp_secret_raw = random_base64_secret()
    buzz_key_raw = os.urandom(32)
    beacon = request_json(
        "POST",
        f"{args.base_url}/beacon",
        token=dev_token,
        body={
            "serialNumber": random.randint(10000, 99999),
            "signatureKey": base64.b64encode(buzz_key_raw).decode("ascii"),
            "totpKey": totp_secret_b64,
            "programVersion": f"v-seed-{seed}",
        },
    )
    beacon_serial = str(beacon["serialNumber"])
    state["created"]["beacon_id"] = beacon["id"]
    state["totp_secret_b64"] = totp_secret_b64

    request_json(
        "POST",
        f"{args.base_url}/beacon/{beacon['id']}/classroom",
        token=admin_token,
        body={"classroomId": classroom["id"]},
    )

    teacher_token = login(args.base_url, teacher["email"], teacher_password)
    student_tokens = [login(args.base_url, s["email"],
                            student_password) for s in students]

    signers = []
    for student, token in zip(students, student_tokens):
        private_key = ec.generate_private_key(ec.SECP256R1())
        signer = DeviceSigner(
            student["id"], f"device-{seed}-{student['id'][:6]}", private_key)
        request_json(
            "POST",
            f"{args.base_url}/students/me/devices",
            token=token,
            body={"device_identifier": signer.device_id,
                  "public_key": signer.public_key_pem()},
        )
        print("public key pem:", signer.public_key_pem())
        signers.append(signer)

    teacher_sig = request_json(
        "POST",
        f"{args.base_url}/signature",
        token=teacher_token,
        body={
            "date": now_unix(),
            "course": course["id"],
            "status": "present",
            "method": "self",
            "teacher": teacher["id"],
            "image": base64.b64encode(b"teacher-image").decode("ascii"),
        },
    )
    state["created"]["signatures"].append(teacher_sig["id"])

    absent_sig = request_json(
        "POST",
        f"{args.base_url}/signature",
        token=teacher_token,
        body={
            "date": now_unix(),
            "course": course["id"],
            "status": "absent",
            "method": "self",
            "student": students[0]["id"],
            "teacher": teacher["id"],
        },
    )
    state["created"]["signatures"].append(absent_sig["id"])

    extra_teacher_sig = request_json(
        "POST",
        f"{args.base_url}/signature",
        token=teacher_token,
        body={
            "date": now_unix(),
            "course": extra_course["id"],
            "status": "present",
            "method": "self",
            "teacher": teacher["id"],
        },
    )
    state["created"]["signatures"].append(extra_teacher_sig["id"])

    buzz_student = students[1]
    buzz_token = student_tokens[1]
    buzz_signer = signers[1]

    buzz_code = request_with_device(
        "GET",
        args.base_url,
        "/signature/buzzlightyear",
        buzz_token,
        buzz_signer,
    )
    buzz_cmac = CMAC(algorithms.AES(buzz_key_raw))
    buzz_cmac.update(str(buzz_code["code"]).encode("utf-8"))
    buzz_signature = base64.b64encode(buzz_cmac.finalize()).decode("ascii")
    buzz_challenge = request_with_device(
        "POST",
        args.base_url,
        f"/signature/buzzlightyear/{beacon_serial}",
        buzz_token,
        buzz_signer,
        body={"signature": buzz_signature, "courseId": course["id"]},
    )
    buzz_sig = request_with_device(
        "POST",
        args.base_url,
        "/signature",
        buzz_token,
        buzz_signer,
        body={
            "date": now_unix(),
            "course": course["id"],
            "status": "signed",
            "method": "buzzLightyear",
            "student": buzz_student["id"],
            "challenge": buzz_challenge["challenge"],
        },
    )
    state["created"]["signatures"].append(buzz_sig["id"])

    nfc_student = students[2]
    nfc_token = student_tokens[2]
    nfc_signer = signers[2]

    server_time = get_server_time(args.base_url, admin_token)
    debug_code = None
    debug_generated_at = None
    try:
        debug_resp = request_json(
            "GET",
            f"{args.base_url}/signature/nfcCode/{beacon_serial}/debug",
            token=admin_token,
        )
        debug_code = debug_resp.get("totpCode")
        debug_generated_at = debug_resp.get("generatedAt")
        if debug_code:
            print(
                f"NFC debug code (server): {debug_code} at {debug_generated_at}")
    except Exception as err:
        print(f"NFC debug endpoint unavailable: {err}")

    if debug_code:
        server_ts = server_time.timestamp()
        local_base64 = totp(totp_secret_raw, server_ts)
        print(f"NFC local base64 code (auth time): {local_base64}")
        if debug_generated_at is not None:
            try:
                debug_ts = float(debug_generated_at)
                drift = debug_ts - server_ts
                print(f"NFC time drift (debug - auth): {drift:.0f}s")
                local_base64_dbg = totp(totp_secret_raw, debug_ts)
                print(
                    f"NFC local base64 code (debug time): {local_base64_dbg}")
            except (TypeError, ValueError):
                pass

    nfc_code = debug_code or totp(totp_secret_raw, time.time())
    nfc_challenge = request_with_device(
        "POST",
        args.base_url,
        f"/signature/nfcCode/{beacon_serial}",
        nfc_token,
        nfc_signer,
        body={"courseId": course["id"], "totpCode": nfc_code},
    )
    nfc_sig = request_with_device(
        "POST",
        args.base_url,
        "/signature",
        nfc_token,
        nfc_signer,
        body={
            "date": now_unix(),
            "course": course["id"],
            "status": "signed",
            "method": "nfc",
            "student": nfc_student["id"],
            "challenge": nfc_challenge["challenge"],
        },
    )
    state["created"]["signatures"].append(nfc_sig["id"])

    print("Running negative tests...")
    # Missing device headers should fail.
    resp = request_with_custom_headers(
        "GET",
        args.base_url,
        "/signature/buzzlightyear",
        buzz_token,
    )
    expect_error(resp, "device_not_allowed")

    # Invalid device signature should fail.
    bad_headers = buzz_signer.sign_headers(
        "GET", "/signature/buzzlightyear", b"")
    bad_headers["X-Device-Signature"] = base64.b64encode(
        os.urandom(64)).decode("ascii")
    resp = request_with_custom_headers(
        "GET",
        args.base_url,
        "/signature/buzzlightyear",
        buzz_token,
        headers=bad_headers,
    )
    expect_error(resp, "device_signature_invalid")

    # Challenge should not be reusable across courses.
    temp_code = request_with_device(
        "GET",
        args.base_url,
        "/signature/buzzlightyear",
        buzz_token,
        buzz_signer,
    )
    temp_cmac = CMAC(algorithms.AES(buzz_key_raw))
    temp_cmac.update(str(temp_code["code"]).encode("utf-8"))
    temp_signature = base64.b64encode(temp_cmac.finalize()).decode("ascii")
    temp_challenge = request_with_device(
        "POST",
        args.base_url,
        f"/signature/buzzlightyear/{beacon_serial}",
        buzz_token,
        buzz_signer,
        body={"signature": temp_signature, "courseId": course["id"]},
    )
    mismatch_resp = request_with_device_response(
        "POST",
        args.base_url,
        "/signature",
        buzz_token,
        buzz_signer,
        body={
            "date": now_unix(),
            "course": extra_course["id"],
            "status": "signed",
            "method": "buzzLightyear",
            "student": buzz_student["id"],
            "challenge": temp_challenge["challenge"],
        },
    )
    expect_error(mismatch_resp, "challenge_mismatch")

    # Reusing a consumed challenge should fail.
    reuse_resp = request_with_device_response(
        "POST",
        args.base_url,
        "/signature",
        buzz_token,
        buzz_signer,
        body={
            "date": now_unix(),
            "course": extra_course["id"],
            "status": "signed",
            "method": "buzzLightyear",
            "student": buzz_student["id"],
            "challenge": temp_challenge["challenge"],
        },
    )
    expect_error(reuse_resp, "challenge_missing")

    save_state(args.state_file, state)

    print("Simulation complete.")
    print(f"Seed: {seed}")
    print(f"State file: {args.state_file}")
    print(f"Buzzlightyear code: {buzz_code['code']}")


if __name__ == "__main__":
    main()
