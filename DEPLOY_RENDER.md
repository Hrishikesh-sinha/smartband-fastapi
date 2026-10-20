# Deploying to the cloud (Render + PostgreSQL)

Result: `https://YOUR-SERVICE.onrender.com` serves the dashboard and receives signed
readings from the band over HTTPS. Data is stored in a cloud PostgreSQL database.

## 0. Prepare the secrets on your laptop (PowerShell, inside backend\)
```
python manage.py add-device smartband-01      (skip if already done)
python manage.py cloud-env
```
Copy the two printed values (DEVICE_SECRETS and DASHBOARD_TOKEN) into Notepad.

## 1. Put the code on GitHub
1. Create a free account at github.com -> New repository -> name `smartband-fastapi` -> Private -> Create.
2. "uploading an existing file" -> drag in the contents of a FRESHLY EXTRACTED zip
   (backend, tools, firmware, requirements.txt, README.md, DEPLOY_RENDER.md, START_SERVER.bat).
   Never upload device_secrets.json, smartband.db or secrets.h.
3. Commit changes.

## 2. Create the database on Render
1. Sign up at render.com with your GitHub account.
2. New + -> PostgreSQL. Name: `smartband-db`. Region: Singapore. Plan: Free. Create.
3. When it is ready, copy the **Internal Database URL**.

## 3. Create the web service
New + -> Web Service -> choose the `smartband-fastapi` repository, then:

| Setting | Value |
|---|---|
| Region | Singapore (same as the database) |
| Runtime / Language | Python 3 |
| Build Command | `pip install -r requirements.txt` |
| Start Command | `cd backend && uvicorn main:app --host 0.0.0.0 --port $PORT --proxy-headers --forwarded-allow-ips="*"` |
| Instance type | Free |

Environment variables (Add Environment Variable):

| Key | Value |
|---|---|
| DATABASE_URL | the Internal Database URL from step 2 |
| DEVICE_SECRETS | from `python manage.py cloud-env` |
| DASHBOARD_TOKEN | from `python manage.py cloud-env` |
| PYTHON_VERSION | 3.12.7 |

Create Web Service. After the build shows "Live", open
`https://YOUR-SERVICE.onrender.com/health` -> `{"status":"ok"}`, then the main address for the dashboard.

## 4. Test the cloud deployment from the laptop
```
python tools\security_tests.py smartband-01 DEVICE-SECRET DASHBOARD-TOKEN --url https://YOUR-SERVICE.onrender.com
```

## Notes
- Free web services sleep after a period without traffic; the first request can take up to a minute.
  Open the dashboard a few minutes before the demo.
- Check Render's current free-plan limits: free databases may expire after a limited period.
- Secrets live only in Render's environment settings, never in GitHub.
