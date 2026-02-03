#!/usr/bin/env python3
import argparse
import base64
import concurrent.futures
import datetime as dt
import json
import os
import random
import re
import threading
import unicodedata
import uuid
from pathlib import Path


DATA_DIR = Path(__file__).resolve().parent / "data"
NORMALIZED_DIR = DATA_DIR / "normalized"

DEFAULT_BASE_URL = os.getenv(
    "SEMAPHORE_BASE_URL", "https://semaphore.deway.fr").strip()
DEFAULT_DEV_EMAIL = os.getenv(
    "SEMAPHORE_DEV_EMAIL", "dev@semaphore.fr").strip()
DEFAULT_DEV_PASSWORD = os.getenv(
    "SEMAPHORE_DEV_PASSWORD", "dev-password").strip()
DEFAULT_USER_PASSWORD = "dev-password"
DEFAULT_BEACON_VERSION = "1.1.2-beacon-os"

SIGNATURE_STATUSES = ["signed", "present",
                      "absent", "late", "excused", "invalid"]
SIGNATURE_METHODS = {
    "signed": "nfc",
    "present": "teacher",
    "absent": "admin",
    "late": "web",
    "excused": "self",
    "invalid": "beacon",
}
SIGNATURE_METHOD_VALUES = [
    "nfc",
    "beacon",
    "buzzLightyear",
    "teacher",
    "web",
    "self",
    "admin",
]


def require_requests():
    try:
        import requests  # type: ignore
    except ImportError as exc:
        raise SystemExit(
            "Missing dependency: requests. Install with: pip install requests"
        ) from exc
    return requests


def require_crypto():
    try:
        from cryptography.hazmat.primitives import serialization  # type: ignore
        from cryptography.hazmat.primitives.asymmetric import ec  # type: ignore
    except ImportError as exc:
        raise SystemExit(
            "Missing dependency: cryptography. Install with: pip install cryptography"
        ) from exc
    return serialization, ec


def read_lines(path: Path):
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def slugify(value: str) -> str:
    value = unicodedata.normalize("NFKD", value)
    value = value.encode("ascii", "ignore").decode("ascii")
    value = value.lower()
    value = re.sub(r"[^a-z0-9]+", "-", value).strip("-")
    return value or "item"


def unique_key(base: str, used: set[str]) -> str:
    if base not in used:
        used.add(base)
        return base
    index = 2
    while True:
        candidate = f"{base}-{index}"
        if candidate not in used:
            used.add(candidate)
            return candidate
        index += 1


def split_name(full_name: str):
    parts = full_name.split()
    if not parts:
        return "", ""
    if len(parts) == 1:
        return parts[0], ""
    return " ".join(parts[:-1]), parts[-1]


def generate_email(first_name: str, last_name: str, used: set[str]) -> str:
    base = f"{first_name} {last_name}".strip()
    slug = slugify(base).replace("-", ".")
    if not slug:
        slug = "user"
    email = f"seed.{slug}@semaphore.fr"
    if email not in used:
        used.add(email)
        return email
    index = 2
    while True:
        candidate = f"seed.{slug}.{index}@semaphore.fr"
        if candidate not in used:
            used.add(candidate)
            return candidate
        index += 1


def parse_school_md(path: Path):
    name = None
    preference_text = ""
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if ":" not in line:
                continue
            label, value = line.split(":", 1)
            label = label.strip().lower()
            value = value.strip()
            if "school name" in label:
                name = value
            if "school preference" in label:
                preference_text = value.lower()
    if not name:
        name = "Semaphore School"

    delay = 15
    match = re.search(r"(\d+)", preference_text)
    if match:
        delay = int(match.group(1))

    authorize_all = "authorize" in preference_text or "all" in preference_text

    preferences = {
        "defaultSignatureClosingDelay": delay,
        "teacherCanModifyClosingdelay": True,
        "studentsCanSignBeforeTeacher": authorize_all,
        "nfcEnabled": True,
        "flashlightEnabled": True,
        "disableCourseModificationFromUI": False,
    }
    return name, preferences


def parse_beacon_md(path: Path):
    if not path.exists():
        return DEFAULT_BEACON_VERSION
    text = path.read_text(encoding="utf-8")
    match = re.search(
        r'scripts_version name should be\s+"([^"]+)"', text, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return DEFAULT_BEACON_VERSION


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2,
                    ensure_ascii=False) + "\n", encoding="utf-8")


def index_by_key(items):
    return {item.get("key"): item for item in items if item.get("key")}


def merge_entry(existing, fresh, preserve_fields):
    merged = dict(fresh)
    for field in preserve_fields:
        if field in existing:
            merged[field] = existing[field]
    return merged


def generate_ec_keypair():
    serialization, ec = require_crypto()
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return private_pem, public_pem


def generate_random_secret(length=32):
    raw = os.urandom(length)
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def next_available_serial(used_serials: set[int], start: int) -> int:
    if len(used_serials) >= 900000:
        raise SystemExit("No available 6-digit serial numbers left.")
    candidate = start
    while True:
        if candidate < 100000 or candidate > 999999:
            candidate = 100000
        if candidate not in used_serials:
            used_serials.add(candidate)
            return candidate
        candidate += 1


def normalize_data(force: bool, beacon_count: int | None):
    NORMALIZED_DIR.mkdir(parents=True, exist_ok=True)

    existing = {}
    for name in [
        "schools",
        "admins",
        "teachers",
        "students",
        "groups",
        "classrooms",
        "courses",
        "beacons",
        "signatures",
    ]:
        path = NORMALIZED_DIR / f"{name}.json"
        if path.exists() and not force:
            existing[name] = load_json(path)
        else:
            existing[name] = []

    school_name, preferences = parse_school_md(DATA_DIR / "school.md")
    school_key = slugify(school_name)

    schools = [{"key": school_key, "name": school_name,
                "preferences": preferences}]

    used_admin_keys = set(index_by_key(existing["admins"]).keys())
    used_teacher_keys = set(index_by_key(existing["teachers"]).keys())
    used_student_keys = set(index_by_key(existing["students"]).keys())
    used_group_keys = set(index_by_key(existing["groups"]).keys())
    used_classroom_keys = set(index_by_key(existing["classrooms"]).keys())
    used_beacon_keys = set(index_by_key(existing["beacons"]).keys())
    used_serials = set()
    for entry in existing["beacons"]:
        serial = entry.get("serialNumber")
        if isinstance(serial, int):
            used_serials.add(serial)

    used_emails = set()
    for bucket in ["admins", "teachers", "students"]:
        for entry in existing[bucket]:
            email = entry.get("email")
            if email:
                used_emails.add(email)

    admin_existing = index_by_key(existing["admins"])
    admins = []
    admin_names = read_lines(DATA_DIR / "admin.txt")
    admin_roles = ["planning", "absence", "manager"]
    for idx, full_name in enumerate(admin_names):
        first, last = split_name(full_name)
        base_key = slugify(full_name)
        key = base_key if base_key in admin_existing else unique_key(
            base_key, used_admin_keys)
        entry = {
            "key": key,
            "firstName": first,
            "lastName": last,
            "email": generate_email(first, last, used_emails),
            "password": DEFAULT_USER_PASSWORD,
            "role": admin_roles[idx % len(admin_roles)],
            "schoolKey": school_key,
        }
        if key in admin_existing:
            entry = merge_entry(admin_existing[key], entry, [
                                "email", "password", "role"])
        admins.append(entry)

    teacher_existing = index_by_key(existing["teachers"])
    teachers = []
    teacher_names = read_lines(DATA_DIR / "teachers.txt")
    for full_name in teacher_names:
        first, last = split_name(full_name)
        base_key = slugify(full_name)
        key = base_key if base_key in teacher_existing else unique_key(
            base_key, used_teacher_keys)
        entry = {
            "key": key,
            "firstName": first,
            "lastName": last,
            "email": generate_email(first, last, used_emails),
            "password": DEFAULT_USER_PASSWORD,
            "schoolKey": school_key,
        }
        if key in teacher_existing:
            entry = merge_entry(teacher_existing[key], entry, [
                                "email", "password"])
        teachers.append(entry)

    student_existing = index_by_key(existing["students"])
    students = []
    student_names = read_lines(DATA_DIR / "students.txt")
    student_number_start = 100000
    for idx, full_name in enumerate(student_names):
        first, last = split_name(full_name)
        base_key = slugify(full_name)
        key = base_key if base_key in student_existing else unique_key(
            base_key, used_student_keys)
        student_number = student_number_start + idx
        private_key, public_key = generate_ec_keypair()
        entry = {
            "key": key,
            "firstName": first,
            "lastName": last,
            "email": generate_email(first, last, used_emails),
            "password": DEFAULT_USER_PASSWORD,
            "studentNumber": student_number,
            "schoolKey": school_key,
            "device": {
                "deviceIdentifier": f"{key}-device",
                "publicKey": public_key,
                "privateKey": private_key,
            },
            "groups": [],
        }
        if key in student_existing:
            entry = merge_entry(
                student_existing[key],
                entry,
                ["email", "password", "studentNumber", "device"],
            )
        students.append(entry)

    course_names = read_lines(DATA_DIR / "course.txt")

    group_existing = index_by_key(existing["groups"])
    groups = []
    group_names = read_lines(DATA_DIR / "group_name.txt")
    for name in group_names:
        base_key = slugify(name)
        key = base_key if base_key in group_existing else unique_key(
            base_key, used_group_keys)
        entry = {
            "key": key,
            "name": name,
            "singleStudentGroup": False,
            "schoolKey": school_key,
            "students": [],
        }
        if key in group_existing:
            entry = merge_entry(group_existing[key], entry, [])
        groups.append(entry)

    groups_by_key = {g["key"]: g for g in groups}
    for student in students:
        student["groups"] = []

    active_groups = []
    if groups:
        target_group_count = len(course_names) if course_names else len(groups)
        desired_group_count = max(
            3, min(target_group_count, max(1, len(students) // 3)))
        active_groups = groups[: min(len(groups), desired_group_count)]

    if active_groups:
        group_count = len(active_groups)
        groups_per_student = 2 if group_count >= 2 else 1
        offset = group_count // 2 if group_count >= 2 else 0
        for idx, student in enumerate(students):
            primary = active_groups[idx % group_count]
            primary["students"].append(student["key"])
            student["groups"].append(primary["key"])

            if groups_per_student == 2:
                secondary = active_groups[(idx + offset) % group_count]
                if secondary["key"] != primary["key"]:
                    secondary["students"].append(student["key"])
                    student["groups"].append(secondary["key"])

    classroom_existing = index_by_key(existing["classrooms"])
    classrooms = []
    classroom_names = read_lines(DATA_DIR / "classroom.txt")
    for name in classroom_names:
        base_key = slugify(name)
        key = base_key if base_key in classroom_existing else unique_key(
            base_key, used_classroom_keys)
        entry = {
            "key": key,
            "name": name,
            "schoolKey": school_key,
        }
        if key in classroom_existing:
            entry = merge_entry(classroom_existing[key], entry, [])
        classrooms.append(entry)

    course_existing = index_by_key(existing["courses"])
    courses = []
    now = dt.datetime.now(dt.timezone.utc)
    day_offsets = list(range(-10, 11))
    slot_hours = [[8, 0], [9, 0], [11, 30], [13, 40], [16, 0], [18, 0]]
    course_repeat = 4
    course_catalog = []
    for _ in range(course_repeat):
        course_catalog.extend(course_names)
    used_course_keys = set()
    for idx, name in enumerate(course_catalog):
        base_key = slugify(name)
        key = unique_key(base_key, used_course_keys)
        day_index = idx % len(day_offsets)
        slot_index = (idx // len(day_offsets)) % len(slot_hours)
        day_offset = day_offsets[day_index]
        slot_hour = slot_hours[slot_index]
        day = (now + dt.timedelta(days=day_offset)).date()
        start = dt.datetime(
            day.year,
            day.month,
            day.day,
            slot_hour[0],
            slot_hour[1],
            0,
            tzinfo=dt.timezone.utc,
        )
        end = start + dt.timedelta(minutes=90)
        teacher_key = teachers[idx %
                               len(teachers)]["key"] if teachers else None
        classroom_key = classrooms[idx % len(
            classrooms)]["key"] if classrooms else None
        group_pool = active_groups if active_groups else groups
        group_key = group_pool[idx %
                               len(group_pool)]["key"] if group_pool else None
        entry = {
            "key": key,
            "name": name,
            "schoolKey": school_key,
            "date": int(start.timestamp()),
            "endDate": int(end.timestamp()),
            "isOnline": False,
            "teachers": [teacher_key] if teacher_key else [],
            "classrooms": [classroom_key] if classroom_key else [],
            "studentGroups": [group_key] if group_key else [],
        }
        if key in course_existing:
            entry = merge_entry(course_existing[key], entry, [
                "date",
                "endDate",
                "teachers",
                "classrooms",
                "studentGroups",
            ])
        courses.append(entry)

    beacon_existing = index_by_key(existing["beacons"])
    beacons = []
    program_version = parse_beacon_md(DATA_DIR / "beacon.md")
    if beacon_count is None:
        beacon_count = len(classrooms)
    for idx in range(beacon_count):
        classroom_key = classrooms[idx % len(
            classrooms)]["key"] if classrooms else None
        base_key = f"beacon-{classroom_key or idx + 1}"
        key = base_key if base_key in beacon_existing else unique_key(
            base_key, used_beacon_keys)
        serial_number = next_available_serial(used_serials, 100000 + idx)
        entry = {
            "key": key,
            "serialNumber": serial_number,
            "signatureKey": generate_random_secret(32),
            "totpKey": generate_random_secret(20),
            "programVersion": program_version,
            "classroomKey": classroom_key,
        }
        if key in beacon_existing:
            entry = merge_entry(beacon_existing[key], entry, [
                "serialNumber",
                "signatureKey",
                "totpKey",
                "programVersion",
                "classroomKey",
            ])
            preserved_serial = entry.get("serialNumber")
            if isinstance(preserved_serial, int):
                used_serials.add(preserved_serial)
        beacons.append(entry)

    signatures = []
    image_files = [p.name for p in (
        DATA_DIR / "signatures").glob("*") if p.is_file()]
    status_count = len(SIGNATURE_STATUSES)
    sig_index = 0
    now_ts = int(dt.datetime.now(dt.timezone.utc).timestamp())
    for course in courses:
        if course["date"] > now_ts:
            continue
        group_keys = course.get("studentGroups") or []
        student_keys = set()
        for group_key in group_keys:
            group = groups_by_key.get(group_key)
            if group and group.get("students"):
                student_keys.update(group["students"])

        if not student_keys:
            continue

        teacher_key = course.get("teachers", [None])[0]
        admin_key = admins[0]["key"] if admins else None
        for student_key in sorted(student_keys):
            status = SIGNATURE_STATUSES[sig_index % status_count]
            method = SIGNATURE_METHODS.get(status, "web")
            image_file = None
            if status == "signed":
                if not image_files:
                    raise SystemExit(
                        "No images found in scripts/data/signatures for signed signatures.")
                image_file = image_files[sig_index % len(image_files)]

            signatures.append({
                "key": f"signature-{course['key']}-{student_key}",
                "courseKey": course["key"],
                "studentKey": student_key,
                "teacherKey": teacher_key,
                "adminKey": admin_key if status == "absent" else None,
                "status": status,
                "method": method,
                "offsetMinutes": 5 + (sig_index % 20) * 3,
                "imageFile": image_file,
            })
            sig_index += 1

        if teacher_key:
            if not image_files:
                raise SystemExit(
                    "No images found in scripts/data/signatures for signed signatures.")
            signatures.append({
                "key": f"signature-teacher-{course['key']}-{teacher_key}",
                "courseKey": course["key"],
                "teacherKey": teacher_key,
                "signatureType": "teacher",
                "status": "signed",
                "method": random.choice(SIGNATURE_METHOD_VALUES),
                "offsetMinutes": 8,
                "imageFile": image_files[sig_index % len(image_files)],
            })

    write_json(NORMALIZED_DIR / "schools.json", schools)
    write_json(NORMALIZED_DIR / "admins.json", admins)
    write_json(NORMALIZED_DIR / "teachers.json", teachers)
    write_json(NORMALIZED_DIR / "students.json", students)
    write_json(NORMALIZED_DIR / "groups.json", groups)
    write_json(NORMALIZED_DIR / "classrooms.json", classrooms)
    write_json(NORMALIZED_DIR / "courses.json", courses)
    write_json(NORMALIZED_DIR / "beacons.json", beacons)
    write_json(NORMALIZED_DIR / "signatures.json", signatures)

    print("Normalized data written to", NORMALIZED_DIR)


class ApiClient:
    def __init__(self, base_url: str):
        self.base_url = normalize_base_url(base_url)
        self.requests = require_requests()

    def request(self, method: str, path: str, token: str | None = None, body=None, headers=None):
        headers = dict(headers or {})
        if token:
            headers["Authorization"] = f"Bearer {token}"
        url = f"{self.base_url}{path}"
        if body is not None:
            headers["Content-Type"] = "application/json"
            resp = self.requests.request(
                method, url, headers=headers, json=body)
        else:
            resp = self.requests.request(method, url, headers=headers)
        if resp.status_code >= 400:
            raise RuntimeError(
                f"{method} {url} failed ({resp.status_code}): {resp.text}")
        if resp.text:
            return resp.json()
        return None

    def login(self, email: str, password: str) -> str:
        data = self.request("POST", "/auth/login",
                            body={"email": email, "password": password})
        return data["accessToken"]


class StateStore:
    def __init__(self, path: Path):
        self.path = path
        if path.exists():
            self.data = json.loads(path.read_text(encoding="utf-8"))
        else:
            self.data = {}

    def get(self, category: str, key: str):
        return self.data.get(category, {}).get(key)

    def set(self, category: str, key: str, value: str):
        self.data.setdefault(category, {})[key] = value

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(
            self.data, indent=2) + "\n", encoding="utf-8")


def normalize_base_url(base_url: str) -> str:
    base_url = base_url.strip().rstrip("/")
    if not base_url:
        raise SystemExit(
            "Missing base URL. Provide --base-url or SEMAPHORE_BASE_URL.")
    if not base_url.startswith("http://") and not base_url.startswith("https://"):
        base_url = f"https://{base_url}"
    return base_url


def load_normalized():
    payload = {}
    for name in [
        "schools",
        "admins",
        "teachers",
        "students",
        "groups",
        "classrooms",
        "courses",
        "beacons",
        "signatures",
    ]:
        path = NORMALIZED_DIR / f"{name}.json"
        if not path.exists():
            raise SystemExit(f"Missing normalized file: {path}")
        payload[name] = load_json(path)
    return payload


class Progress:
    def __init__(self, label: str, total: int):
        self.label = label
        self.total = max(1, total)
        self.current = 0
        self._lock = threading.Lock()

    def step(self, message: str = ""):
        with self._lock:
            self.current += 1
            width = 28
            filled = int(width * self.current / self.total)
            bar = "#" * filled + "-" * (width - filled)
            suffix = f" {message}" if message else ""
            print(
                f"\r{self.label}: [{bar}] {self.current}/{self.total}{suffix}", end="", flush=True)
            if self.current >= self.total:
                print()


def make_progress(label: str, total: int) -> Progress | None:
    if total <= 0:
        return None
    return Progress(label, total)


def run_concurrent(items, worker, max_workers: int):
    if max_workers <= 1 or len(items) <= 1:
        for item in items:
            worker(item)
        return
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(max_workers, len(items))
    ) as executor:
        futures = [executor.submit(worker, item) for item in items]
        for future in concurrent.futures.as_completed(futures):
            future.result()


def update_state(state: "StateStore", lock: threading.Lock, category: str, key: str, value: str):
    with lock:
        state.set(category, key, value)
        state.save()


def ensure_school(client: ApiClient, token: str, school: dict, state: StateStore):
    key = school["key"]
    existing_id = state.get("schools", key)
    if existing_id:
        return existing_id
    schools = client.request("GET", "/schools", token=token) or []
    for entry in schools:
        if entry.get("name", "").strip().lower() == school["name"].strip().lower():
            state.set("schools", key, entry["id"])
            state.save()
            return entry["id"]
    created = client.request(
        "POST", "/school", token=token, body={"name": school["name"]})
    school_id = created["id"]
    state.set("schools", key, school_id)
    state.save()
    if school.get("preferences"):
        client.request(
            "PATCH",
            f"/school/{school_id}/preferences",
            token=token,
            body=school["preferences"],
        )
    return school_id


def ensure_admins(
    client: ApiClient,
    token: str,
    school_id: str,
    admins: list,
    state: StateStore,
    progress: Progress | None = None,
    state_lock: threading.Lock | None = None,
    max_workers: int = 1,
):
    existing = client.request("GET", f"/admins/{school_id}", token=token) or []
    by_email = {entry.get("email", "").lower(): entry for entry in existing}

    def worker(admin):
        key = admin["key"]
        if state.get("admins", key):
            if progress:
                progress.step(admin["key"])
            return
        email = admin["email"].lower()
        if email in by_email:
            if state_lock:
                update_state(state, state_lock, "admins",
                             key, by_email[email]["id"])
            else:
                state.set("admins", key, by_email[email]["id"])
                state.save()
            if progress:
                progress.step(admin["key"])
            return
        payload = {
            "email": admin["email"],
            "password": admin["password"],
            "firstname": admin["firstName"],
            "lastname": admin["lastName"],
            "createdOn": int(dt.datetime.now(dt.timezone.utc).timestamp()),
            "role": admin["role"],
            "school": school_id,
        }
        created = client.request("POST", "/admin", token=token, body=payload)
        if state_lock:
            update_state(state, state_lock, "admins", key, created["id"])
        else:
            state.set("admins", key, created["id"])
            state.save()
        if progress:
            progress.step(admin["key"])

    run_concurrent(admins, worker, max_workers)


def ensure_teachers(
    client: ApiClient,
    token: str,
    school_id: str,
    teachers: list,
    state: StateStore,
    progress: Progress | None = None,
    state_lock: threading.Lock | None = None,
    max_workers: int = 1,
):
    existing = client.request(
        "GET", f"/teachers/{school_id}", token=token) or []
    by_email = {entry.get("email", "").lower(): entry for entry in existing}

    def worker(teacher):
        key = teacher["key"]
        if state.get("teachers", key):
            if progress:
                progress.step(teacher["key"])
            return
        email = teacher["email"].lower()
        if email in by_email:
            if state_lock:
                update_state(state, state_lock, "teachers",
                             key, by_email[email]["id"])
            else:
                state.set("teachers", key, by_email[email]["id"])
                state.save()
            if progress:
                progress.step(teacher["key"])
            return
        payload = {
            "email": teacher["email"],
            "password": teacher["password"],
            "firstname": teacher["firstName"],
            "lastname": teacher["lastName"],
            "createdOn": int(dt.datetime.now(dt.timezone.utc).timestamp()),
            "school": school_id,
        }
        created = client.request("POST", "/teacher", token=token, body=payload)
        if state_lock:
            update_state(state, state_lock, "teachers", key, created["id"])
        else:
            state.set("teachers", key, created["id"])
            state.save()
        if progress:
            progress.step(teacher["key"])

    run_concurrent(teachers, worker, max_workers)


def ensure_students(
    client: ApiClient,
    token: str,
    school_id: str,
    students: list,
    state: StateStore,
    progress: Progress | None = None,
    state_lock: threading.Lock | None = None,
    max_workers: int = 1,
):
    existing = client.request(
        "GET", f"/students/{school_id}", token=token) or []
    by_email = {entry.get("email", "").lower(): entry for entry in existing}

    def worker(student):
        key = student["key"]
        if state.get("students", key):
            if progress:
                progress.step(student["key"])
            return
        email = student["email"].lower()
        if email in by_email:
            if state_lock:
                update_state(state, state_lock, "students",
                             key, by_email[email]["id"])
            else:
                state.set("students", key, by_email[email]["id"])
                state.save()
            if progress:
                progress.step(student["key"])
            return
        payload = {
            "email": student["email"],
            "password": student["password"],
            "firstname": student["firstName"],
            "lastname": student["lastName"],
            "createdOn": int(dt.datetime.now(dt.timezone.utc).timestamp()),
            "studentNumber": student["studentNumber"],
            "school": school_id,
        }
        created = client.request("POST", "/student", token=token, body=payload)
        if state_lock:
            update_state(state, state_lock, "students", key, created["id"])
        else:
            state.set("students", key, created["id"])
            state.save()
        if progress:
            progress.step(student["key"])

    run_concurrent(students, worker, max_workers)


def ensure_devices(
    client: ApiClient,
    token: str,
    students: list,
    state: StateStore,
    progress: Progress | None = None,
    max_workers: int = 1,
):

    def worker(student):
        student_id = state.get("students", student["key"])
        if not student_id:
            if progress:
                progress.step(student["key"])
            return
        try:
            client.request("GET", f"/student/{student_id}/device", token=token)
            if progress:
                progress.step(student["key"])
            return
        except RuntimeError as exc:
            if "404" not in str(exc):
                raise
        student_token = client.login(student["email"], student["password"])
        device = student.get("device") or {}
        payload = {
            "device_identifier": device.get("deviceIdentifier"),
            "public_key": device.get("publicKey"),
        }
        if not payload["device_identifier"]:
            raise SystemExit(
                f"Missing device identifier for {student['email']}")
        client.request("POST", "/students/me/devices",
                       token=student_token, body=payload)
        if progress:
            progress.step(student["key"])

    run_concurrent(students, worker, max_workers)


def ensure_groups(
    client: ApiClient,
    token: str,
    school_id: str,
    groups: list,
    state: StateStore,
    progress: Progress | None = None,
    state_lock: threading.Lock | None = None,
    max_workers: int = 1,
):
    existing = client.request(
        "GET", f"/studentGroups/{school_id}", token=token) or []
    by_name = {entry.get("name", "").lower(): entry for entry in existing}

    def worker(group):
        key = group["key"]
        if state.get("groups", key):
            if progress:
                progress.step(group["key"])
            return
        name = group["name"].lower()
        if name in by_name:
            if state_lock:
                update_state(state, state_lock, "groups",
                             key, by_name[name]["id"])
            else:
                state.set("groups", key, by_name[name]["id"])
                state.save()
            if progress:
                progress.step(group["key"])
            return
        payload = {
            "name": group["name"],
            "singleStudentGroup": group.get("singleStudentGroup", False),
            "school": school_id,
        }
        created = client.request(
            "POST", "/studentGroup", token=token, body=payload)
        if state_lock:
            update_state(state, state_lock, "groups", key, created["id"])
        else:
            state.set("groups", key, created["id"])
            state.save()
        if progress:
            progress.step(group["key"])

    run_concurrent(groups, worker, max_workers)


def ensure_group_memberships(
    client: ApiClient,
    token: str,
    groups: list,
    state: StateStore,
    progress: Progress | None = None,
    max_workers: int = 1,
):

    def worker(group):
        group_id = state.get("groups", group["key"])
        if not group_id:
            if progress:
                progress.step(group["key"])
            return
        current = client.request(
            "GET", f"/studentGroup/{group_id}?include=students", token=token) or {}
        existing_students = {entry.get("id")
                             for entry in current.get("students", [])}
        desired_ids = []
        for student_key in group.get("students", []):
            student_id = state.get("students", student_key)
            if student_id and student_id not in existing_students:
                desired_ids.append(student_id)
        if not desired_ids:
            if progress:
                progress.step(group["key"])
            return
        payload = {"studentsIds": desired_ids}
        client.request(
            "POST", f"/studentGroup/{group_id}/students", token=token, body=payload)
        if progress:
            progress.step(group["key"])

    run_concurrent(groups, worker, max_workers)


def ensure_classrooms(
    client: ApiClient,
    token: str,
    school_id: str,
    classrooms: list,
    state: StateStore,
    progress: Progress | None = None,
    state_lock: threading.Lock | None = None,
    max_workers: int = 1,
):
    existing = client.request(
        "GET", f"/classrooms/{school_id}", token=token) or []
    by_name = {entry.get("name", "").lower(): entry for entry in existing}

    def worker(room):
        key = room["key"]
        if state.get("classrooms", key):
            if progress:
                progress.step(room["key"])
            return
        name = room["name"].lower()
        if name in by_name:
            if state_lock:
                update_state(state, state_lock, "classrooms",
                             key, by_name[name]["id"])
            else:
                state.set("classrooms", key, by_name[name]["id"])
                state.save()
            if progress:
                progress.step(room["key"])
            return
        payload = {"name": room["name"], "school": school_id}
        created = client.request("POST", "/classroom",
                                 token=token, body=payload)
        if state_lock:
            update_state(state, state_lock, "classrooms", key, created["id"])
        else:
            state.set("classrooms", key, created["id"])
            state.save()
        if progress:
            progress.step(room["key"])

    run_concurrent(classrooms, worker, max_workers)


def build_existing_courses_index(client: ApiClient, admin_token: str):
    try:
        courses = client.request(
            "GET",
            "/courses?from=2000-01-01&to=2100-01-01&limit=500",
            token=admin_token,
        )
    except RuntimeError:
        return {}
    index = {}
    for course in courses or []:
        key = (course.get("name", "").lower(),
               course.get("date"), course.get("endDate"))
        index[key] = course
    return index


def ensure_courses(
    client: ApiClient,
    token: str,
    admin_token: str | None,
    courses: list,
    state: StateStore,
    id_map: dict,
    progress: Progress | None = None,
    state_lock: threading.Lock | None = None,
    max_workers: int = 1,
):
    existing_index = build_existing_courses_index(
        client, admin_token) if admin_token else {}

    def worker(course):
        key = course["key"]
        if state.get("courses", key):
            if progress:
                progress.step(course["key"])
            return
        lookup_key = (course["name"].lower(),
                      course["date"], course["endDate"])
        if lookup_key in existing_index:
            if state_lock:
                update_state(state, state_lock, "courses", key,
                             existing_index[lookup_key]["id"])
            else:
                state.set("courses", key, existing_index[lookup_key]["id"])
                state.save()
            if progress:
                progress.step(course["key"])
            return
        payload = {
            "name": course["name"],
            "date": course["date"],
            "endDate": course["endDate"],
            "isOnline": course.get("isOnline", False),
            "school": id_map["school_id"],
            "classroomsId": [state.get("classrooms", k) for k in course.get("classrooms", []) if state.get("classrooms", k)],
            "teachersId": [state.get("teachers", k) for k in course.get("teachers", []) if state.get("teachers", k)],
            "studentGroupsId": [state.get("groups", k) for k in course.get("studentGroups", []) if state.get("groups", k)],
        }
        created = client.request("POST", "/course", token=token, body=payload)
        if state_lock:
            update_state(state, state_lock, "courses", key, created["id"])
        else:
            state.set("courses", key, created["id"])
            state.save()
        if progress:
            progress.step(course["key"])

    run_concurrent(courses, worker, max_workers)


def ensure_beacons(
    client: ApiClient,
    token: str,
    beacons: list,
    state: StateStore,
    progress: Progress | None = None,
    state_lock: threading.Lock | None = None,
    max_workers: int = 1,
):
    existing = client.request("GET", "/beacons", token=token) or []
    by_serial = {entry.get("serialNumber"): entry for entry in existing}

    def worker(beacon):
        key = beacon["key"]
        if state.get("beacons", key):
            if progress:
                progress.step(beacon["key"])
            return
        serial = beacon["serialNumber"]
        if serial in by_serial:
            if state_lock:
                update_state(state, state_lock, "beacons",
                             key, by_serial[serial]["id"])
            else:
                state.set("beacons", key, by_serial[serial]["id"])
                state.save()
            if progress:
                progress.step(beacon["key"])
            return
        classroom_id = state.get("classrooms", beacon.get(
            "classroomKey")) if beacon.get("classroomKey") else None
        payload = {
            "serialNumber": serial,
            "signatureKey": beacon["signatureKey"],
            "totpKey": beacon["totpKey"],
            "programVersion": beacon["programVersion"],
        }
        if classroom_id:
            payload["classroom"] = classroom_id
        created = client.request("POST", "/beacon", token=token, body=payload)
        if state_lock:
            update_state(state, state_lock, "beacons", key, created["id"])
        else:
            state.set("beacons", key, created["id"])
            state.save()
        if progress:
            progress.step(beacon["key"])

    run_concurrent(beacons, worker, max_workers)


def seed_data(
    base_url: str,
    dev_email: str,
    dev_password: str,
    state_path: Path,
    skip_devices: bool,
    concurrency: int,
):
    client = ApiClient(base_url)
    token = client.login(dev_email, dev_password)

    data = load_normalized()
    state = StateStore(state_path)

    school = data["schools"][0]
    state_lock = threading.Lock()
    school_progress = make_progress("School", 1)
    school_id = ensure_school(client, token, school, state)
    if school_progress:
        school_progress.step(school["key"])

    ensure_admins(
        client,
        token,
        school_id,
        data["admins"],
        state,
        progress=make_progress("Admins", len(data["admins"])),
        state_lock=state_lock,
        max_workers=concurrency,
    )
    ensure_teachers(
        client,
        token,
        school_id,
        data["teachers"],
        state,
        progress=make_progress("Teachers", len(data["teachers"])),
        state_lock=state_lock,
        max_workers=concurrency,
    )
    ensure_students(
        client,
        token,
        school_id,
        data["students"],
        state,
        progress=make_progress("Students", len(data["students"])),
        state_lock=state_lock,
        max_workers=concurrency,
    )

    admin_token = None
    if data["admins"]:
        admin = data["admins"][0]
        admin_token = client.login(admin["email"], admin["password"])

    if not skip_devices:
        ensure_devices(
            client,
            token,
            data["students"],
            state,
            progress=make_progress("Devices", len(data["students"])),
            max_workers=concurrency,
        )

    ensure_groups(
        client,
        token,
        school_id,
        data["groups"],
        state,
        progress=make_progress("Groups", len(data["groups"])),
        state_lock=state_lock,
        max_workers=concurrency,
    )
    groups_with_students = [g for g in data["groups"] if g.get("students")]
    ensure_group_memberships(
        client,
        token,
        groups_with_students,
        state,
        progress=make_progress("Group members", len(groups_with_students)),
        max_workers=concurrency,
    )
    ensure_classrooms(
        client,
        token,
        school_id,
        data["classrooms"],
        state,
        progress=make_progress("Classrooms", len(data["classrooms"])),
        state_lock=state_lock,
        max_workers=concurrency,
    )
    ensure_courses(
        client,
        token,
        admin_token,
        data["courses"],
        state,
        {"school_id": school_id},
        progress=make_progress("Courses", len(data["courses"])),
        state_lock=state_lock,
        max_workers=concurrency,
    )
    ensure_beacons(
        client,
        token,
        data["beacons"],
        state,
        progress=make_progress("Beacons", len(data["beacons"])),
        state_lock=state_lock,
        max_workers=concurrency,
    )

    print("Seeding completed. State saved to", state_path)


def safe_delete(client: ApiClient, token: str, path: str) -> bool:
    try:
        client.request("DELETE", path, token=token)
        return True
    except RuntimeError as exc:
        text = str(exc)
        if "404" in text or "not_found" in text:
            return False
        raise


def cleanup_data(base_url: str, dev_email: str, dev_password: str, state_path: Path, keep_state: bool):
    if not state_path.exists():
        print("No state file found:", state_path)
        return

    client = ApiClient(base_url)
    token = client.login(dev_email, dev_password)
    state = StateStore(state_path)

    def delete_category(label: str, category: str, path_fmt: str):
        ids = list(state.data.get(category, {}).values())
        progress = make_progress(label, len(ids))
        for item_id in ids:
            safe_delete(client, token, path_fmt.format(item_id))
            if progress:
                progress.step(item_id)

    delete_category("Beacons", "beacons", "/beacon/{}")
    delete_category("Courses", "courses", "/course/{}")
    delete_category("Classrooms", "classrooms", "/classroom/{}")
    delete_category("Groups", "groups", "/studentGroup/{}")
    delete_category("Students", "students", "/student/{}")
    delete_category("Teachers", "teachers", "/teacher/{}")
    delete_category("Admins", "admins", "/admin/{}")
    delete_category("Schools", "schools", "/school/{}")

    if keep_state:
        print("Cleanup completed. State file kept:", state_path)
        return

    state_path.unlink(missing_ok=True)
    print("Cleanup completed. State file removed:", state_path)


def sql_quote(value: str | None):
    if value is None:
        return "NULL"
    return "'" + value.replace("'", "''") + "'"


def load_image_data_urls():
    image_dir = DATA_DIR / "signatures"
    data_urls = {}
    if not image_dir.exists():
        return data_urls
    for path in image_dir.iterdir():
        if not path.is_file():
            continue
        ext = path.suffix.lower().lstrip(".") or "png"
        mime = f"image/{ext}"
        raw = path.read_bytes()
        encoded = base64.b64encode(raw).decode("ascii")
        data_urls[path.name] = f"data:{mime};base64,{encoded}"
    return data_urls


def generate_signature_sql(state_path: Path, output_path: Path):
    data = load_normalized()
    state = StateStore(state_path)

    courses = {c["key"]: c for c in data["courses"]}
    images = load_image_data_urls()

    lines = []
    lines.append("-- Generated by scripts/seed_database.py")
    lines.append("BEGIN;")

    namespace = uuid.UUID("00000000-0000-0000-0000-000000000123")

    for entry in data["signatures"]:
        course_key = entry.get("courseKey")
        if not course_key:
            continue

        sig_type = entry.get("signatureType") or "student"
        course_id = state.get("courses", course_key)
        if not course_id:
            continue

        course = courses[course_key]
        start_time = dt.datetime.fromtimestamp(
            course["date"], tz=dt.timezone.utc)
        signed_at = start_time + \
            dt.timedelta(minutes=entry.get("offsetMinutes", 0))
        signed_at_sql = signed_at.strftime("%Y-%m-%d %H:%M:%S+00")

        status = entry.get("status") or "signed"
        method = entry.get("method") or SIGNATURE_METHODS.get(status, "web")

        image_url = None
        if status == "signed":
            image_name = entry.get("imageFile")
            if not image_name:
                raise SystemExit(
                    f"Signed signature missing imageFile for {course_key}.")
            image_url = images.get(image_name)
            if not image_url:
                raise SystemExit(f"Signature image not found: {image_name}")

        if sig_type == "teacher":
            teacher_key = entry.get("teacherKey")
            if not teacher_key:
                continue
            teacher_id = state.get("teachers", teacher_key)
            if not teacher_id:
                continue
            admin_id = state.get("admins", entry.get(
                "adminKey")) if entry.get("adminKey") else None

            signature_id = str(
                uuid.uuid5(namespace, f"{course_id}:{teacher_id}:teacher"))

            lines.append(
                "INSERT INTO signatures (id, course_id, signed_at, status, method, image_url, created_at)"
            )
            lines.append(
                "SELECT {id}, {course_id}, timestamptz '{signed_at}', {status}, {method}, {image_url}, now()"
                " WHERE NOT EXISTS (SELECT 1 FROM signatures WHERE id = {id});".format(
                    id=sql_quote(signature_id),
                    course_id=sql_quote(course_id),
                    signed_at=signed_at_sql,
                    status=sql_quote(status),
                    method=sql_quote(method),
                    image_url=sql_quote(image_url),
                )
            )

            lines.append(
                "INSERT INTO teacher_signatures (signature_id, teacher_id, administrator_id, course_id)"
            )
            lines.append(
                "SELECT {sig_id}, {teacher_id}, {admin_id}, {course_id}"
                " WHERE NOT EXISTS (SELECT 1 FROM teacher_signatures WHERE signature_id = {sig_id});".format(
                    sig_id=sql_quote(signature_id),
                    teacher_id=sql_quote(teacher_id),
                    admin_id=sql_quote(admin_id),
                    course_id=sql_quote(course_id),
                )
            )
            continue

        student_key = entry.get("studentKey")
        if not student_key:
            continue
        student_id = state.get("students", student_key)
        if not student_id:
            continue
        teacher_id = state.get("teachers", entry.get(
            "teacherKey")) if entry.get("teacherKey") else None
        admin_id = state.get("admins", entry.get(
            "adminKey")) if entry.get("adminKey") else None

        signature_id = str(uuid.uuid5(namespace, f"{course_id}:{student_id}"))

        lines.append(
            "INSERT INTO signatures (id, course_id, signed_at, status, method, image_url, created_at)"
        )
        lines.append(
            "SELECT {id}, {course_id}, timestamptz '{signed_at}', {status}, {method}, {image_url}, now()"
            " WHERE NOT EXISTS (SELECT 1 FROM signatures WHERE id = {id});".format(
                id=sql_quote(signature_id),
                course_id=sql_quote(course_id),
                signed_at=signed_at_sql,
                status=sql_quote(status),
                method=sql_quote(method),
                image_url=sql_quote(image_url),
            )
        )

        lines.append(
            "INSERT INTO student_signatures (signature_id, student_id, teacher_id, administrator_id, course_id)"
        )
        lines.append(
            "SELECT {sig_id}, {student_id}, {teacher_id}, {admin_id}, {course_id}"
            " WHERE NOT EXISTS (SELECT 1 FROM student_signatures WHERE signature_id = {sig_id});".format(
                sig_id=sql_quote(signature_id),
                student_id=sql_quote(student_id),
                teacher_id=sql_quote(teacher_id),
                admin_id=sql_quote(admin_id),
                course_id=sql_quote(course_id),
            )
        )

    lines.append("COMMIT;")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("Signature SQL written to", output_path)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Normalize and seed Semaphore data from scripts/data")
    sub = parser.add_subparsers(dest="command", required=True)

    normalize = sub.add_parser(
        "normalize", help="Generate normalized JSON files")
    normalize.add_argument("--force", action="store_true",
                           help="Overwrite existing normalized JSON files")
    normalize.add_argument("--beacon-count", type=int,
                           help="Number of beacons to generate")

    seed = sub.add_parser("seed", help="Seed data via API")
    seed.add_argument("--base-url", default=DEFAULT_BASE_URL,
                      help="Base API URL")
    seed.add_argument(
        "--dev-email", default=DEFAULT_DEV_EMAIL, help="Dev email")
    seed.add_argument("--dev-password",
                      default=DEFAULT_DEV_PASSWORD, help="Dev password")
    seed.add_argument("--state-file", default=str(NORMALIZED_DIR /
                      "state.json"), help="State file path")
    seed.add_argument("--skip-devices", action="store_true",
                      help="Skip student device registration")
    seed.add_argument("--concurrency", type=int, default=6,
                      help="Max concurrent API calls per phase")

    cleanup = sub.add_parser(
        "cleanup", help="Remove previously seeded data via API")
    cleanup.add_argument("--base-url", default=DEFAULT_BASE_URL,
                         help="Base API URL")
    cleanup.add_argument(
        "--dev-email", default=DEFAULT_DEV_EMAIL, help="Dev email")
    cleanup.add_argument("--dev-password",
                         default=DEFAULT_DEV_PASSWORD, help="Dev password")
    cleanup.add_argument("--state-file", default=str(NORMALIZED_DIR /
                         "state.json"), help="State file path")
    cleanup.add_argument("--keep-state", action="store_true",
                         help="Keep the state file after cleanup")

    sig = sub.add_parser("generate-signature-sql",
                         help="Generate attendance signature SQL")
    sig.add_argument("--state-file", default=str(NORMALIZED_DIR /
                     "state.json"), help="State file path")
    sig.add_argument(
        "--output",
        default=str(NORMALIZED_DIR / "attendance_signatures_seed.sql"),
        help="Output SQL file path",
    )

    all_cmd = sub.add_parser(
        "all", help="Run normalize, seed, and signature SQL generation")
    all_cmd.add_argument("--force", action="store_true",
                         help="Overwrite existing normalized JSON files")
    all_cmd.add_argument("--beacon-count", type=int,
                         help="Number of beacons to generate")
    all_cmd.add_argument(
        "--base-url", default=DEFAULT_BASE_URL, help="Base API URL")
    all_cmd.add_argument(
        "--dev-email", default=DEFAULT_DEV_EMAIL, help="Dev email")
    all_cmd.add_argument(
        "--dev-password", default=DEFAULT_DEV_PASSWORD, help="Dev password")
    all_cmd.add_argument(
        "--state-file", default=str(NORMALIZED_DIR / "state.json"), help="State file path")
    all_cmd.add_argument("--skip-devices", action="store_true",
                         help="Skip student device registration")
    all_cmd.add_argument("--concurrency", type=int, default=6,
                         help="Max concurrent API calls per phase")
    all_cmd.add_argument(
        "--signature-sql",
        default=str(NORMALIZED_DIR / "attendance_signatures_seed.sql"),
        help="Output SQL file path",
    )

    return parser.parse_args()


def main():
    args = parse_args()
    if args.command == "normalize":
        normalize_data(force=args.force, beacon_count=args.beacon_count)
        return
    if args.command == "seed":
        seed_data(
            base_url=args.base_url,
            dev_email=args.dev_email,
            dev_password=args.dev_password,
            state_path=Path(args.state_file),
            skip_devices=args.skip_devices,
            concurrency=args.concurrency,
        )
        return
    if args.command == "generate-signature-sql":
        generate_signature_sql(Path(args.state_file), Path(args.output))
        return
    if args.command == "cleanup":
        cleanup_data(
            base_url=args.base_url,
            dev_email=args.dev_email,
            dev_password=args.dev_password,
            state_path=Path(args.state_file),
            keep_state=args.keep_state,
        )
        return
    if args.command == "all":
        normalize_data(force=args.force, beacon_count=args.beacon_count)
        seed_data(
            base_url=args.base_url,
            dev_email=args.dev_email,
            dev_password=args.dev_password,
            state_path=Path(args.state_file),
            skip_devices=args.skip_devices,
            concurrency=args.concurrency,
        )
        generate_signature_sql(Path(args.state_file), Path(args.signature_sql))
        return


if __name__ == "__main__":
    main()
