# Performance baseline: what does the driver cost code that is not hooked?
#
#   bare   driver stopped
#   vmx    driver running, no profile
#   hooks  hidden profile on (kernel hooks + win32k window hooks)
#
#   .\scripts\Bench.ps1
#
# Results go to .cache\bench.log.
[CmdletBinding()]
param([uint32]$Mask = 0x1FF)
$ErrorActionPreference = "Continue"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$OutDir = Join-Path $RepoRoot "build\windows\x64\releasedbg"
$Loader = Join-Path $OutDir "blook-loader.exe"
$Driver = Join-Path $OutDir "blook-drv.sys"
$Bench = Join-Path $OutDir "blook-bench.exe"
$Key = "HKLM:\SYSTEM\CurrentControlSet\Services\BlookDrv"
$Log = Join-Path $RepoRoot ".cache\bench.log"

function Write-Log([string]$text) {
    Write-Host $text
    if (-not (Test-Path -LiteralPath (Split-Path -Parent $Log))) { New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Log) | Out-Null }
    $fs = [IO.File]::Open($Log, "Append", "Write", "ReadWrite")
    $sw = New-Object IO.StreamWriter($fs)
    $sw.WriteLine(((Get-Date -Format "yyyy-MM-dd HH:mm:ss") + " " + $text))
    $sw.Flush(); $fs.Flush($true); $sw.Close(); $fs.Close()
}
# Never pipe a native command into a cmdlet here: PowerShell treats some of them
# as "documents" and refuses ("Cannot run a document in the middle of a pipeline").
# Capture the output and log it line by line instead.
function Logged([string]$label, [scriptblock]$body) {
    Write-Log ("--- " + $label)
    $out = & $body 2>&1
    foreach ($line in $out) { Write-Log ("  " + [string]$line) }
}

Push-Location -LiteralPath $RepoRoot
try {
    Logged "bare: driver stopped" { & $Loader stop }
    Write-Log "--- bare: bench"
    $null = & $Bench --log $Log

    Logged "vmx: install + start, no profile" {
        & $Loader stop
        & $Loader uninstall
        & $Loader install $Driver
        Set-ItemProperty -LiteralPath $Key -Name HookMask -Value $Mask -Type DWord
        Set-ItemProperty -LiteralPath $Key -Name WindowHookMask -Value 0 -Type DWord
        & $Loader start
    }
    Write-Log "--- vmx: bench"
    $null = & $Bench --log $Log

    Logged "hooks: hidden profile on" {
        & $Loader hide on
        & $Loader hide windows on
        & $Loader status
    }
    Write-Log "--- hooks: bench"
    $null = & $Bench --log $Log

    Logged "cleanup" {
        & $Loader hide windows off
        & $Loader hide off
        & $Loader stop
    }
    Write-Log "=== bench.ps1: done"
} finally {
    Pop-Location
}

