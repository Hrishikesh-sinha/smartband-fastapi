"""Simulated band: signs readings exactly like the ESP32 firmware.

  python tools/send_reading.py smartband-01 SECRET_HEX --pulse 76 --mq 420
The sequence number is kept in tools/<device>.seq so it never repeats.
"""
import argparse
import hashlib
import hmac
import json
import os

import requests

HERE = os.path.dirname(os.path.abspath(__file__))


def sign(secret: bytes, device: str, seq: int, body: bytes) -> str:
    return hmac.new(secret, f"{device}\n{seq}\n".encode() + body, hashlib.sha256).hexdigest()


def next_seq(device: str) -> int:
    path = os.path.join(HERE, device + ".seq")
    seq = (int(open(path).read()) if os.path.exists(path) else 0) + 1
    open(path, "w").write(str(seq))
    return seq


def post(url, device, seq, body, sig):
    return requests.post(url + "/api/readings", data=body, timeout=10, headers={
        "Content-Type": "application/json", "X-Device-Id": device,
        "X-Sequence": str(seq), "X-Signature": sig})


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("device")
    ap.add_argument("secret_hex")
    ap.add_argument("--pulse", type=int, default=76)
    ap.add_argument("--mq", type=int, default=420)
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    a = ap.parse_args()
    seq = next_seq(a.device)
    body = json.dumps({"pulse_bpm": a.pulse, "mq135_raw": a.mq}, separators=(",", ":")).encode()
    r = post(a.url, a.device, seq, body, sign(bytes.fromhex(a.secret_hex), a.device, seq, body))
    print(f"seq {seq} -> {r.status_code} {r.text}")
