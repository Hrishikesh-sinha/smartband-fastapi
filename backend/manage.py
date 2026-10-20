"""Admin commands (run inside the backend folder).

  python manage.py add-device smartband-01      register a band, print its secret once
  python manage.py disable-device smartband-01  revoke a lost or compromised band
  python manage.py add-user doctor1             create a dashboard login token (shown once)
  python manage.py list                         show devices and users (no secrets)

For the cloud (Render), copy these into the service's Environment settings:
  python manage.py cloud-env                    prints DEVICE_SECRETS and a new DASHBOARD_TOKEN
"""
import hashlib
import json
import os
import secrets
import sys

import database as db
import device_auth


def save_devices(devs):
    with open(device_auth.SECRETS_PATH, "w") as f:
        json.dump(devs, f, indent=2)
    try:
        os.chmod(device_auth.SECRETS_PATH, 0o600)   # owner-only on Linux/macOS
    except OSError:
        pass


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    cmd = sys.argv[1]
    db.init_db()
    devs = device_auth.load_devices()

    if cmd == "add-device" and len(sys.argv) == 3:
        dev = sys.argv[2]
        if dev in devs:
            sys.exit(f"{dev} is already registered")
        secret = secrets.token_bytes(32)
        devs[dev] = {"secret_hex": secret.hex(), "active": True}
        save_devices(devs)
        db.log_event("device_registered", dev, "registered by admin")
        print(f"Registered {dev}. Secret (shown once; put it in the band's secrets.h):\n{secret.hex()}")
    elif cmd == "disable-device" and len(sys.argv) == 3:
        dev = sys.argv[2]
        if dev not in devs:
            sys.exit("no such device")
        devs[dev]["active"] = False
        save_devices(devs)
        db.log_event("device_disabled", dev, "disabled by admin")
        print(f"{dev} disabled")
    elif cmd == "add-user" and len(sys.argv) == 3:
        token = secrets.token_urlsafe(32)
        con = db.connect()
        con.execute("INSERT INTO dashboard_users VALUES (?,?)",
                    (sys.argv[2], hashlib.sha256(token.encode()).hexdigest()))
        con.close()
        print(f"Dashboard token for {sys.argv[2]} (shown once, only its hash is stored):\n{token}")
    elif cmd == "cloud-env":
        active = {d: v["secret_hex"] for d, v in devs.items() if v.get("active", True)}
        if not active:
            sys.exit("Register the band first: python manage.py add-device smartband-01")
        print("Add these two environment variables in Render (Environment tab). Keep them private.\n")
        print("Key:   DEVICE_SECRETS")
        print("Value: " + json.dumps(active, separators=(",", ":")) + "\n")
        print("Key:   DASHBOARD_TOKEN")
        print("Value: " + secrets.token_urlsafe(32))
        print("\n(The dashboard token is new: use it to sign in to the cloud dashboard.)")
    elif cmd == "list":
        for d, v in devs.items():
            print(f"device {d:<16} {'active' if v.get('active', True) else 'DISABLED'}")
        con = db.connect()
        for r in con.execute("SELECT username FROM dashboard_users"):
            print(f"user   {r['username']}")
        con.close()
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
