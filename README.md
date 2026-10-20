# Privacy-Preserving Smart Band (FastAPI backend)

Backend for the privacy-preserving smart band. Runs locally with SQLite and on the cloud
(Render) with PostgreSQL; see DEPLOY_RENDER.md.

Features: HMAC-SHA-256 device authentication, persistent per-device
sequence numbers (replay protection), input validation, security-event logging, and
token-protected dashboard endpoints.

## Run on Windows (PowerShell, inside this folder)

```
pip install -r requirements.txt
cd backend
python manage.py add-device smartband-01
python manage.py add-user doctor1
uvicorn main:app --host 0.0.0.0 --port 8000
```
Save the device secret and the dashboard token in Notepad (each is shown once).
Check it is running: open http://127.0.0.1:8000/health

## Security tests (second PowerShell window, project folder)

```
python tools\security_tests.py smartband-01 DEVICE-SECRET DASHBOARD-TOKEN
```

## API
| Endpoint | Access |
|---|---|
| GET /health | public |
| POST /api/readings | registered device + valid HMAC + new sequence number |
| GET /api/readings/latest, /api/readings | dashboard token |
| GET /api/security-events | dashboard token |

Signed bytes: `device_id + "\n" + sequence + "\n" + body`. Headers: X-Device-Id, X-Sequence, X-Signature.
Device secrets are kept in backend/device_secrets.json, not in the database.

## Demo without typing

1. Double-click `START_SERVER.bat`. The dashboard opens in Chrome at http://127.0.0.1:8000/
2. Paste the dashboard token once and click Sign in.
3. Use the Attack demo buttons. Each sends a real request to the server; results and
   security events appear on the page. Demo requests use the separate ID `smartband-demo`,
   so the real band's sequence numbers are never disturbed. Set DEMO_MODE=0 to switch it off.
