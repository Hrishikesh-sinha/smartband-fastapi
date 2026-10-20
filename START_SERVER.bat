@echo off
title Smart Band Secure Server
cd /d "%~dp0backend"
echo Starting the secure server...  Keep this window open during the demo.
start "" cmd /c "timeout /t 4 >nul & start http://127.0.0.1:8000/"
python -m uvicorn main:app --host 0.0.0.0 --port 8000
echo.
echo The server stopped. If you see an error above, take a screenshot.
pause
