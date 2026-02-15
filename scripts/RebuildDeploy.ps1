$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition

Write-Host ">>> Rebuilding..." -ForegroundColor Cyan
xmake f -m releasedbg -c
xmake -r

if ($LASTEXITCODE -eq 0) {
    Write-Host ">>> Build successful, signing..." -ForegroundColor Green
    . "$PSScriptRoot\Sign.ps1"
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host ">>> Signing successful, deploying..." -ForegroundColor Green
        . "$PSScriptRoot\Deploy.ps1"
    }
}