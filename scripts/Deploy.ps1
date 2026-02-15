$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition

. "$PSScriptRoot\Config.ps1"

Write-Host ">>> Deploying to Local Machine" -ForegroundColor Green

$DriverPath = "$BuildOutputDir\$DriverName.sys"
$KlhkPath = ".\src\klhk.sys"
$DestPath = "C:\"

# Copy driver files to C:\
Write-Host ">>> Copying driver files..." -ForegroundColor Yellow
Copy-Item -Path $DriverPath -Destination "$DestPath$DriverName.sys" -Force
Copy-Item -Path $KlhkPath -Destination "${DestPath}klhk.sys" -Force

# Create and configure klhk service
Write-Host ">>> Configuring klhk service..." -ForegroundColor Yellow
sc.exe create klhk binPath= "C:\klhk.sys" type= kernel start= demand error= normal DisplayName= "Kaspersky Lab service driver" 2>$null | Out-Null

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\klhk\Parameters"
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
New-ItemProperty -Path $regPath -Name "UseHvm" -Value 1 -PropertyType DWord -Force | Out-Null

# Create driver service
Write-Host ">>> Configuring $DriverName service..." -ForegroundColor Yellow
sc.exe create $DriverName binPath= "C:\$DriverName.sys" type= kernel start= demand error= normal DisplayName= "$DriverName Service" 2>$null | Out-Null

# Start services
Write-Host ">>> Starting klhk..." -ForegroundColor Cyan
sc.exe start klhk

Write-Host ">>> Starting $DriverName..." -ForegroundColor Cyan
sc.exe start $DriverName

Write-Host ">>> Deployment Complete!" -ForegroundColor Green