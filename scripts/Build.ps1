# The whole build pipeline in one place:
#
#   (stop a running driver) -> configure -> build -> host tests -> sign ->
#   (reinstall and restart what was running, or with -Deploy/-Start).
#
# A loaded driver locks its image, so a plain build stops it first and starts
# it again afterwards; no flags are needed to replace a running driver.
#
# Signing is part of the build: the signer runs silently on every build and
# rewrites the image's Authenticode signature in place. Whether that signature
# is acceptable is settled by the kernel loading the driver, not by a separate
# verification pass.
#
#   .\scripts\Build.ps1              build + test + sign
#   .\scripts\Build.ps1 -Deploy      ... and install the service
#   .\scripts\Build.ps1 -Start       ... and start it (virtualises every CPU!)
#   .\scripts\Build.ps1 -NoTests     skip all host test suites
#   .\scripts\Build.ps1 -NoSign -BuildDir build/refactor-check  isolated artifacts
#   .\scripts\Build.ps1 -NoSign      skip signing (bring-up only)
[CmdletBinding()]
param(
    [switch]$Deploy,
    [switch]$Start,
    [switch]$NoTests,
    [switch]$NoSign,
    [ValidateNotNullOrEmpty()]
    [string]$BuildDir = "build"
)
# Native tools write diagnostics to stderr; with "Stop" PowerShell turns that
# into a terminating error before the exit code is even inspected, so every
# step below checks $LASTEXITCODE itself and throws explicitly.
$ErrorActionPreference = "Continue"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$BuildRoot = if ([IO.Path]::IsPathRooted($BuildDir)) { $BuildDir } else { Join-Path $RepoRoot $BuildDir }
$OutDir = Join-Path $BuildRoot "windows\x64\releasedbg"
$Driver = Join-Path $OutDir "blook-drv.sys"
$Loader = Join-Path $OutDir "blook-loader.exe"
$Log = Join-Path $RepoRoot ".cache\build.log"

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
$xmake = Require-Tool "xmake"

Push-Location -LiteralPath $RepoRoot
try {
    # A running driver locks its image file, so the link step below would fail
    # with LNK1104. Stop and uninstall it up front; the install/start stages
    # at the end bring it back. This is what lets a plain `Build.ps1` replace
    # a loaded driver in one go.
    $service = Get-Service BlookDrv -ErrorAction SilentlyContinue
    $driverWasRunning = $service -and $service.Status -ne "Stopped"
    if ($driverWasRunning) {
        Write-Log "=== build.ps1: stop running driver (it locks the image)"
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) { throw "BlookDrv is running and locks blook-drv.sys; stopping it needs elevation (gsudo)." }
        if (-not (Test-Path -LiteralPath $Loader)) { throw "no $Loader to stop the service with." }
        Logged "stop" { & $Loader stop }
        $service = Get-Service BlookDrv -ErrorAction SilentlyContinue
        if ($service -and $service.Status -ne "Stopped") {
            throw "BlookDrv did not stop (state: $($service.Status)). A stuck unload cannot be cancelled - reboot the machine."
        }
        Logged "uninstall" { & $Loader uninstall }
    }

    Write-Log "=== build.ps1: configure"
    $configure = & $xmake f -p windows -a x64 -m releasedbg -o $BuildRoot -y 2>&1
    foreach ($line in $configure) { Write-Log ("  " + [string]$line) }
    if ($LASTEXITCODE -ne 0) { throw "xmake configure failed ($LASTEXITCODE)." }

    Write-Log "=== build.ps1: build"
    $build = & $xmake build -a 2>&1
    foreach ($line in $build) { Write-Log ("  " + [string]$line) }
    if ($LASTEXITCODE -ne 0) { throw "xmake build failed ($LASTEXITCODE)." }

    if (-not $NoTests) {
        Write-Log "=== build.ps1: host tests"
        foreach ($suite in @("blook-tests", "blook-protocol-tests", "blook-client-tests", "blook-loader-tests")) {
            Write-Log ("  suite: " + $suite)
            $tests = & $xmake run $suite 2>&1
            $testExit = $LASTEXITCODE
            foreach ($line in $tests) { Write-Log ("  " + [string]$line) }
            if ($testExit -ne 0) { throw "$suite failed ($testExit)." }
        }
    }

    if (-not $NoSign) {
        Write-Log "=== build.ps1: sign"
        if (-not (Test-Path -LiteralPath $Driver)) { throw "no $Driver to sign." }
        # spcsign: local Authenticode PKCS#7 builder (SHA-1 + legacy countersignature,
        # byte-for-byte the shape of the legacy vendor signature that passed
        # kernel-policy verification). It rewrites the image's signature in place, so
        # signing an image that is already signed is fine and always ends the same way.
        # The signer ships prebuilt in this repo, so the build never compiles it and
        # never depends on a checkout outside the repo. It finds its SPC templates and
        # local TSA by walking up from its own directory, i.e. signer\spc-templates\
        # and signer\tsa\ next door.
        # Rebuild (only when the signer itself changes):
        #   dotnet publish <spcsign repo>\src\spcsign -c Release -r win-x64 --self-contained false -o signer\spcsign
        $signerExe = Join-Path $RepoRoot "signer\spcsign\spcsign.exe"
        if (-not (Test-Path -LiteralPath $signerExe)) { throw "spcsign.exe not found ($signerExe)." }
        $chainCerts = @(
            (Join-Path $RepoRoot "signer\certs\verisign-cscs-2010.cer"),
            (Join-Path $RepoRoot "signer\certs\verisign-g5-mcvr.cer")
        )
        $signArgs = @("sign", "--sha1", "--cert", "XINDA",
            "--tsa-time", "2013-01-01T00:00:00Z")
        foreach ($cer in $chainCerts) { $signArgs += @("--chain", $cer) }
        $signArgs += $Driver
        $sign = & $signerExe @signArgs 2>&1
        foreach ($line in $sign) { Write-Log ("  " + [string]$line) }
        if ($LASTEXITCODE -ne 0) { throw "spcsign failed ($LASTEXITCODE)." }
    }

    if ($Deploy -or $Start -or $driverWasRunning) {
        Write-Log "=== build.ps1: install"
        Logged "install" { & $Loader install $Driver }
    }
    if ($Start -or $driverWasRunning) {
        Write-Log "=== build.ps1: start (the driver virtualises every logical processor)"
        Logged "start" { & $Loader start }
        Logged "status" { & $Loader status }
    }
    Write-Log "=== build.ps1: done"
} finally {
    Pop-Location
}

