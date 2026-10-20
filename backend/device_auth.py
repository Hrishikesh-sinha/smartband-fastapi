"""Device registry and HMAC-SHA-256 verification.

Device secrets come from (a) the DEVICE_SECRETS environment variable on the cloud host,
JSON like {"smartband-01": "<64 hex chars>"}, and/or (b) device_secrets.json for local
development. They are never stored in the database and never sent over the network.

Signed bytes = device_id + "\\n" + sequence + "\\n" + exact request body bytes, so a valid
body cannot be moved to another device or given a new sequence number.
"""
import hashlib
import hmac
import json
import os

SECRETS_PATH = os.environ.get(
    "SMARTBAND_SECRETS", os.path.join(os.path.dirname(__file__), "device_secrets.json"))
RUNTIME_DEVICES = {}   # e.g. the demo simulator's key, created in memory at startup


def load_devices():
    devs = {}
    if os.path.exists(SECRETS_PATH):
        with open(SECRETS_PATH) as f:
            devs.update(json.load(f))
    env = os.environ.get("DEVICE_SECRETS", "").strip()
    if env:
        for dev, val in json.loads(env).items():
            devs[dev] = {"secret_hex": val, "active": True} if isinstance(val, str) else val
    devs.update(RUNTIME_DEVICES)
    return devs


def signing_bytes(device_id: str, seq: int, body: bytes) -> bytes:
    return f"{device_id}\n{seq}\n".encode() + body


def compute_signature(secret: bytes, device_id: str, seq: int, body: bytes) -> str:
    return hmac.new(secret, signing_bytes(device_id, seq, body), hashlib.sha256).hexdigest()


def get_active_secret(device_id: str):
    dev = load_devices().get(device_id)
    if not dev or not dev.get("active", True):
        return None
    return bytes.fromhex(dev["secret_hex"])


def signature_ok(secret: bytes, device_id: str, seq: int, body: bytes, supplied: str) -> bool:
    expected = compute_signature(secret, device_id, seq, body)
    return hmac.compare_digest(expected, (supplied or "").strip().lower())   # constant-time
