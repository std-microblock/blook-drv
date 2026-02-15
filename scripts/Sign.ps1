$PSScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition

. "$PSScriptRoot\Config.ps1"

Write-Host ">>> Signing Drivers" -ForegroundColor Green

$FilesToSign = @(
    "$BuildOutputDir\$DriverName.sys"
)

foreach ($File in $FilesToSign) {
    if (Test-Path $File) {
        Write-Host ">>> Signing: $File" -ForegroundColor Yellow
        cd signer
        ./CSignTool.exe sign /r $SignRule /f ../$File /ac
        cd ..

        if ($LASTEXITCODE -eq 0) {
            Write-Host ">>> Signed successfully: $File" -ForegroundColor Green
        } else {
            Write-Host ">>> Failed to sign: $File" -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host ">>> File not found: $File" -ForegroundColor Red
        exit 1
    }
}

Write-Host ">>> All drivers signed successfully!" -ForegroundColor Green
