@echo off
echo Stopping old server on port 5000...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :5000 ^| findstr LISTENING') do (
    echo Killing process %%a
    taskkill /F /PID %%a 2>nul
)
timeout /t 2 /nobreak >nul
echo Starting new server...
cd /d %~dp0
.venv\Scripts\python.exe demo_server\server.py

