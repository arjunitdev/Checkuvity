@echo off
echo Starting Text File Signature Verification Server...
cd /d %~dp0
.venv\Scripts\python.exe demo_server\server.py

