"""Privacy-preserving smart band: FastAPI backend (Phase 1).

Run (from the backend folder):
    uvicorn main:app --host 0.0.0.0 --port 8000

Every reading must pass, in order:
  1. required headers present and well-formed
  2. device registered and active
  3. HMAC-SHA-256 over device_id, sequence and exact body bytes
  4. body fields valid and bounded (only the fields we allow)
  5. sequence number greater than the last accepted one (checked and stored atomically)
Failures are rejected before anything is written to the readings table, and a minimal
security event (no secrets, no sensor values) is recorded instead.
"""
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Optional

import requests

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

import database as db
import device_auth

MAX_BODY_BYTES = 512   # a reading is about 40 bytes

app = FastAPI(title="Privacy-Preserving Smart Band API", version="1.0")
db.init_db()


class Reading(BaseModel):
    """Data minimisation: only these two fields are accepted. No names, no location."""
    model_config = ConfigDict(extra="forbid")
    pulse_bpm: Optional[int] = Field(default=None, ge=30, le=220)   # None = signal not usable
    mq135_raw: int = Field(ge=0, le=4095)                           # raw ADC, not ppm


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "?"


def reject(status: int, event: str, device_id: Optional[str], detail: str, request: Request, public_msg: str):
    db.log_event(event, device_id, detail, client_ip(request))
    raise HTTPException(status_code=status, detail=public_msg)


# ---------- public ----------
@app.get("/health")
def health():
    return {"status": "ok"}


# ---------- device ingestion ----------
@app.post("/api/readings", status_code=201)
async def post_reading(
    request: Request,
    x_device_id: Optional[str] = Header(default=None),
    x_sequence: Optional[str] = Header(default=None),
    x_signature: Optional[str] = Header(default=None),
):
    body = await request.body()
    if len(body) > MAX_BODY_BYTES:
        reject(413, "oversized_request", x_device_id, f"{len(body)} bytes", request, "request too large")

    # 1. headers
    if not x_device_id or not x_sequence or not x_signature:
        reject(400, "missing_headers", x_device_id, "device id, sequence or signature missing",
               request, "missing authentication headers")
    try:
        seq = int(x_sequence)
        if not 1 <= seq <= 2**31 - 1:
            raise ValueError
    except ValueError:
        reject(400, "bad_sequence", x_device_id, "sequence is not a positive integer", request,
               "invalid sequence number")

    # 2. registered device  (same public message as a bad signature: do not reveal which IDs exist)
    secret = device_auth.get_active_secret(x_device_id)
    if secret is None:
        reject(401, "unknown_device", x_device_id, "device not registered or disabled", request,
               "authentication failed")

    # 3. HMAC over the exact bytes received
    if not device_auth.signature_ok(secret, x_device_id, seq, body, x_signature):
        reject(401, "invalid_signature", x_device_id, f"seq {seq}", request, "authentication failed")

    # 4. validate content (only after the sender is authenticated)
    try:
        reading = Reading.model_validate(json.loads(body))
    except (ValueError, ValidationError) as e:
        reject(422, "invalid_payload", x_device_id, str(e).splitlines()[0][:150], request,
               "reading fields invalid or out of range")

    # 5. replay check + store, atomically
    stored, last = db.store_reading_if_new(x_device_id, seq, reading.pulse_bpm, reading.mq135_raw)
    if not stored:
        reject(409, "replay_rejected", x_device_id, f"seq {seq} not greater than last accepted {last}",
               request, "replayed or out-of-order sequence number")

    return {"accepted": True, "device_id": x_device_id, "seq": seq}


# ---------- dashboard access (bearer token, checked on every request) ----------
def require_user(request: Request, authorization: Optional[str] = Header(default=None)) -> str:
    token = authorization[7:].strip() if authorization and authorization.startswith("Bearer ") else ""
    if token:
        env_tok = os.environ.get("DASHBOARD_TOKEN", "")
        if env_tok and hmac.compare_digest(hashlib.sha256(token.encode()).digest(),
                                           hashlib.sha256(env_tok.encode()).digest()):
            return "dashboard"
        con = db.connect()
        row = con.execute("SELECT username FROM dashboard_users WHERE token_hash=?",
                          (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
        con.close()
        if row:
            return row["username"]
    db.log_event("unauthorized_dashboard_access", None, request.url.path, client_ip(request))
    raise HTTPException(status_code=401, detail="login required")


@app.get("/api/readings/latest")
def latest_reading(user: str = Depends(require_user)):
    con = db.connect()
    row = con.execute("SELECT device_id, seq, pulse_bpm, mq135_raw, received_at "
                      "FROM readings ORDER BY id DESC LIMIT 1").fetchone()
    con.close()
    return dict(row) if row else {}


@app.get("/api/readings")
def reading_history(limit: int = 50, user: str = Depends(require_user)):
    limit = max(1, min(limit, 500))
    con = db.connect()
    rows = con.execute("SELECT device_id, seq, pulse_bpm, mq135_raw, received_at "
                       "FROM readings ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    con.close()
    return [dict(r) for r in rows]


@app.get("/api/security-events")
def security_events(limit: int = 50, user: str = Depends(require_user)):
    limit = max(1, min(limit, 500))
    con = db.connect()
    rows = con.execute("SELECT at, event_type, device_id, detail, client_ip "
                       "FROM security_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    con.close()
    return [dict(r) for r in rows]


# ---------- dashboard page ----------
@app.get("/")
def dashboard_page():
    return FileResponse(os.path.join(os.path.dirname(__file__), "dashboard.html"))


# ---------- one-click attack demo (for presentations; disable with DEMO_MODE=0) ----------
DEMO_DEVICE = "smartband-demo"   # separate ID so the demo never disturbs the real band's sequence numbers


# The demo simulator gets a random key held only in memory; it is never written to disk or the database.
device_auth.RUNTIME_DEVICES[DEMO_DEVICE] = {"secret_hex": secrets.token_bytes(32).hex(), "active": True}


def demo_secret() -> bytes:
    return bytes.fromhex(device_auth.RUNTIME_DEVICES[DEMO_DEVICE]["secret_hex"])


def readings_count() -> int:
    con = db.connect()
    n = con.execute("SELECT COUNT(*) AS n FROM readings").fetchone()["n"]
    con.close()
    return n


def next_demo_seq() -> int:
    con = db.connect()
    row = con.execute("SELECT last_seq FROM device_state WHERE device_id=?", (DEMO_DEVICE,)).fetchone()
    con.close()
    return (row["last_seq"] if row else 0) + 1


SCENARIOS = {
    "valid":   ("Valid signed reading", "Accepted and stored"),
    "tamper":  ("Tampering: pulse changed 76 to 180 after signing", "Rejected: signature no longer matches"),
    "replay":  ("Replay: the same signed message sent twice", "First accepted, copy rejected"),
    "unknown": ("Fake device with its own key", "Rejected: device not registered"),
    "invalid": ("Correctly signed but impossible value (pulse 999)", "Rejected: value out of range"),
    "nologin": ("Read patient data without logging in", "Refused: login required"),
}


@app.post("/demo/{scenario}")
def run_demo(scenario: str, request: Request, user: str = Depends(require_user)):
    if os.environ.get("DEMO_MODE", "1") != "1":
        raise HTTPException(status_code=404, detail="demo mode is off")
    if scenario not in SCENARIOS:
        raise HTTPException(status_code=404, detail="unknown scenario")
    # Call this same server directly (inside the host), so requests go through the real ingest checks.
    base = f"http://127.0.0.1:{os.environ.get('PORT') or request.url.port or 8000}"
    key = demo_secret()
    steps = []

    def send(label, dev, seq, body, k, sent_body=None):
        sig = device_auth.compute_signature(k, dev, seq, body)
        before = readings_count()
        r = requests.post(base + "/api/readings", data=sent_body if sent_body is not None else body, timeout=10,
                          headers={"Content-Type": "application/json", "X-Device-Id": dev,
                                                 "X-Sequence": str(seq), "X-Signature": sig})
        steps.append({"label": label, "http": r.status_code, "reply": r.json().get("error", "accepted"),
                      "stored": readings_count() - before})

    def body(pulse, mq=410):
        return json.dumps({"pulse_bpm": pulse, "mq135_raw": mq}, separators=(",", ":")).encode()

    if scenario == "valid":
        send("Signed reading, new sequence number", DEMO_DEVICE, next_demo_seq(), body(76), key)
    elif scenario == "tamper":
        send("Signed with pulse 76, sent with pulse 180", DEMO_DEVICE, next_demo_seq(), body(76), key, body(180))
    elif scenario == "replay":
        seq, b = next_demo_seq(), body(78)
        send(f"Original message (seq {seq})", DEMO_DEVICE, seq, b, key)
        send(f"Same message again (seq {seq})", DEMO_DEVICE, seq, b, key)
    elif scenario == "unknown":
        send("Device 'smartband-99' with a made-up key", "smartband-99", 1, body(76), secrets.token_bytes(32))
    elif scenario == "invalid":
        send("Pulse 999, correctly signed", DEMO_DEVICE, next_demo_seq(), body(999), key)
    elif scenario == "nologin":
        r = requests.get(base + "/api/readings/latest", timeout=10)
        steps.append({"label": "GET /api/readings/latest with no token", "http": r.status_code,
                      "reply": r.json().get("error", "data returned"), "stored": 0})
    title, expected = SCENARIOS[scenario]
    return {"scenario": title, "expected": expected, "steps": steps, "at": int(time.time())}


@app.exception_handler(HTTPException)
async def http_error(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})
