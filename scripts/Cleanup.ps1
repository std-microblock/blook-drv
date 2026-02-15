$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition

. "$PSScriptRoot\Config.ps1"

Write-Host ">>> Stopping and removing services..." -ForegroundColor Yellow

# Stop services
sc.exe stop $DriverName 2>$null | Out-Null
sc.exe stop klhk 2>$null | Out-Null

# Wait for services to stop
Start-Sleep -Seconds 2

# Delete services
sc.exe delete $DriverName 2>$null | Out-Null
sc.exe delete klhk 2>$null | Out-Null

# Remove driver files
Remove-Item -Path "C:\$DriverName.sys" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\klhk.sys" -Force -ErrorAction SilentlyContinue

Write-Host ">>> Cleanup complete!" -ForegroundColor Green
