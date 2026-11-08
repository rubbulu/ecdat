# Start ECDAT Backend Server
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$env:PYTHONPATH = $ScriptDir
$env:PATH = "$env:LOCALAPPDATA\Python\pythoncore-3.14-64\Scripts;$env:LOCALAPPDATA\Python\pythoncore-3.14-64;$env:PATH"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Starting ECDAT Backend Server (FastAPI + Uvicorn)        " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "API documentation will be available at: http://localhost:8000/docs" -ForegroundColor Yellow
Write-Host ""

python -m uvicorn backend.main:app --reload --port 8000
