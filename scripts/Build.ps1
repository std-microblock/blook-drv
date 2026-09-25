# The whole build pipeline in one place:
#
#   configure -> build -> host tests -> sign -> verify -> (optionally) install/start.
#
# Signing is part of the build: the signer runs silently and the result is
# checked with `signtool verify /kp`, so an unsigned driver cannot get out of
# here by accident.
#
#   .\scripts\Build.ps1              build + test + sign + verify
#   .\scripts\Build.ps1 -Deploy      ... and install the service
#   .\scripts\Build.ps1 -Start       ... and start it (virtualises every CPU!)
#   .\scripts\Build.ps1 -NoTests     skip blook-tests
#   .\scripts\Build.ps1 -NoSign      skip signing (bring-up only)
[CmdletBinding()]
param(
    [switch]$Deploy,
    [switch]$Start,
    [switch]$NoTests,
    [switch]$NoSign
)
# Native tools write diagnostics to stderr; with "Stop" PowerShell turns that
# into a terminating error before the exit code is even inspected, so every
# step below checks $LASTEXITCODE itself and throws explicitly.
$ErrorActionPreference = "Continue"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$OutDir = Join-Path $RepoRoot "build\windows\x64\releasedbg"
$Driver = Join-Path $OutDir "blook-drv.sys"
$Loader = Join-Path $OutDir "blook-loader.exe"
$Log = Join-Path $RepoRoot ".cache\build.log"
$SignRule = "r1"

function Write-Log([string]$text) {
    Write-Host $text
    if (-not (Test-Path -LiteralPath (Split-Path -Parent $Log))) { New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Log) | Out-Null }
    $fs = [IO.File]::Open($Log, "Append", "Write", "ReadWrite")
    $sw = New-Object IO.StreamWriter($fs)
    $sw.WriteLine(((Get-Date -Format "yyyy-MM-dd HH:mm:ss") + " " + $text))
    $sw.Flush(); $fs.Flush($true); $sw.Close(); $fs.Close()
}
function Logged([string]$label, [scriptblock]$body) {
    Write-Log ("--- " + $label)
    $out = & $body 2>&1
    foreach ($line in $out) { Write-Log ("  " + [string]$line) }
}
function Require-Tool([string]$name) {
    $tool = Get-Command $name -ErrorAction SilentlyContinue
    if ($tool) { return $tool.Source }
    # xmake is often only installed under the user profile (and then only on the
    # interactive PATH), so look there before giving up.
    foreach ($candidate in @("$env:USERPROFILE\$name\$name.exe", "$env:LOCALAPPDATA\$name\$name.exe")) {
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    throw "$name was not found (PATH, $env:USERPROFILE\$name)."
}
function Find-SignTool {
    $tool = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($tool) { return $tool.Source }
    $roots = @()
    if (${env:ProgramFiles(x86)}) { $roots += (Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin") }
    if ($env:ProgramFiles) { $roots += (Join-Path $env:ProgramFiles "Windows Kits\10\bin") }
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        $found = Get-ChildItem -LiteralPath $root -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match "\\x64\\signtool\.exe$" } | Sort-Object FullName -Descending
        if ($found) { return $found[0].FullName }
    }
    throw "signtool.exe not found."
}

$xmake = Require-Tool "xmake"
$signTool = if ($NoSign) { $null } else { Find-SignTool }

Push-Location -LiteralPath $RepoRoot
try {
    Write-Log "=== build.ps1: configure"
    $configure = & $xmake f -p windows -a x64 -m releasedbg -y 2>&1
    foreach ($line in $configure) { Write-Log ("  " + [string]$line) }
    if ($LASTEXITCODE -ne 0) { throw "xmake configure failed ($LASTEXITCODE)." }

    Write-Log "=== build.ps1: build"
    $build = & $xmake build -a 2>&1
    foreach ($line in $build) { Write-Log ("  " + [string]$line) }
    if ($LASTEXITCODE -ne 0) { throw "xmake build failed ($LASTEXITCODE)." }

    if (-not $NoTests) {
        Write-Log "=== build.ps1: host tests"
        $tests = & $xmake run blook-tests 2>&1
        foreach ($line in $tests) { Write-Log ("  " + [string]$line) }
        if ($LASTEXITCODE -ne 0) { throw "blook-tests failed ($LASTEXITCODE)." }
    }

    if (-not $NoSign) {
        Write-Log "=== build.ps1: sign"
        if (-not (Test-Path -LiteralPath $Driver)) { throw "no $Driver to sign." }
        # The signer refuses to re-sign an already signed image, so a rebuild that
        # changed nothing keeps the existing signature (and its verification).
        $existing = & $signTool verify /kp $Driver 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "  already signed and verified; skipping the signer"
        } else {
            Push-Location -LiteralPath (Join-Path $RepoRoot "signer")
            try {
                $sign = & ".\CSignTool.exe" sign /r $SignRule /f $Driver /ac 2>&1
                foreach ($line in $sign) { Write-Log ("  " + [string]$line) }
                if ($LASTEXITCODE -ne 0) { throw "CSignTool failed ($LASTEXITCODE)." }
            } finally { Pop-Location }
            $verify = & $signTool verify /kp $Driver 2>&1
            foreach ($line in $verify) { Write-Log ("  " + [string]$line) }
            if ($LASTEXITCODE -ne 0) { throw "signature verification failed; the driver would not load." }
        }
    }

    if ($Deploy -or $Start) {
        Write-Log "=== build.ps1: install"
        Logged "stop" { & $Loader stop }
        Logged "uninstall" { & $Loader uninstall }
        Logged "install" { & $Loader install $Driver }
    }
    if ($Start) {
        Write-Log "=== build.ps1: start (the driver virtualises every logical processor)"
        Logged "start" { & $Loader start }
        Logged "status" { & $Loader status }
    }
    Write-Log "=== build.ps1: done"
} finally {
    Pop-Location
}

