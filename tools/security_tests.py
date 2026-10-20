"""Controlled security tests against OUR OWN development server.

  python tools/security_tests.py smartband-01 SECRET_HEX DASHBOARD_TOKEN [--url http://127.0.0.1:8000]

For each test it records: expected result, actual result, HTTP response, database outcome
(readings added) and the security event logged. Results are also saved to tools/test_results.csv.
Test 6 (TLS certificate verification) is run on the ESP32 itself in Phase 3.
"""
import argparse
import csv
import json
import os
import secrets

import requests

from send_reading import next_seq, post, sign

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("device")
    ap.add_argument("secret_hex")
    ap.add_argument("dashboard_token")
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    a = ap.parse_args()
    url, dev, key = a.url.rstrip("/"), a.device, bytes.fromhex(a.secret_hex)
    auth = {"Authorization": "Bearer " + a.dashboard_token}

    def count():
        return len(requests.get(url + "/api/readings?limit=500", headers=auth, timeout=10).json())

    def last_event():
        ev = requests.get(url + "/api/security-events?limit=1", headers=auth, timeout=10).json()
        return ev[0]["event_type"] if ev else "-"

    def body(pulse, mq):
        return json.dumps({"pulse_bpm": pulse, "mq135_raw": mq}, separators=(",", ":")).encode()

    results = []

    def record(name, expected, ok_code, fn):
        before_n, before_ev = count(), last_event()
        r = fn()
        after_n, after_ev = count(), last_event()
        added = after_n - before_n
        event = after_ev if after_ev != before_ev or r.status_code >= 400 else "-"
        passed = r.status_code == ok_code and (added == 1) == (ok_code == 201)
        try:
            msg = r.json().get("error") or "accepted"
        except ValueError:
            msg = r.text[:60]
        results.append([name, expected, f"{r.status_code} {msg}", f"{added:+d} reading(s)", event,
                        "PASS" if passed else "FAIL"])

    # Test 1: valid device, new sequence number
    s1 = next_seq(dev)
    b1 = body(76, 420)
    sig1 = sign(key, dev, s1, b1)
    record("1 Valid device", "201, 1 reading stored", 201, lambda: post(url, dev, s1, b1, sig1))

    # Test 2: tampering - change pulse after signing
    s2 = next_seq(dev)
    sig2 = sign(key, dev, s2, body(76, 420))
    record("2 Data tampering", "401, nothing stored", 401, lambda: post(url, dev, s2, body(180, 420), sig2))

    # Test 3: replay - resend test 1 byte for byte
    record("3 Replay attack", "409, nothing stored", 409, lambda: post(url, dev, s1, b1, sig1))

    # Test 4: unauthorized device with its own made-up key
    fake = "smartband-99"
    record("4 Unauthorized device", "401, nothing stored", 401,
           lambda: post(url, fake, 1, b1, sign(secrets.token_bytes(32), fake, 1, b1)))

    # Extra: correctly signed but impossible value
    s5 = next_seq(dev)
    b5 = body(999, 420)
    record("4b Out-of-range value", "422, nothing stored", 422, lambda: post(url, dev, s5, b5, sign(key, dev, s5, b5)))

    # Test 5: dashboard data without login
    def no_login():
        return requests.get(url + "/api/readings/latest", timeout=10)
    before_n = count()
    r = no_login()
    ev = last_event()
    results.append(["5 Dashboard without login", "401, no data returned", f"{r.status_code} {r.json().get('error')}",
                    f"{count() - before_n:+d} reading(s)", ev, "PASS" if r.status_code == 401 else "FAIL"])

    head = ["Test", "Expected", "Actual HTTP response", "Database outcome", "Security event", "Result"]
    widths = [max(len(str(x)) for x in col) for col in zip(head, *results)]
    for row in [head] + results:
        print("  ".join(str(c).ljust(w) for c, w in zip(row, widths)))
    with open(os.path.join(HERE, "test_results.csv"), "w", newline="") as f:
        csv.writer(f).writerows([head] + results)
    print("\nSaved to tools/test_results.csv")


if __name__ == "__main__":
    main()
