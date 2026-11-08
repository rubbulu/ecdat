# Start ECDAT Frontend Server
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location "$ScriptDir\frontend"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Starting ECDAT Frontend Server (Vite + React)           " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Frontend will be available at: http://localhost:5173" -ForegroundColor Yellow
Write-Host ""

npm run dev
