# Stop and uninstall the driver service. Driver files and other services are
# left alone on purpose.
$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$Loader = Join-Path $RepoRoot "build\windows\x64\releasedbg\blook-loader.exe"
& $Loader stop
if ($LASTEXITCODE -ne 0) { throw "Stop failed; leaving service and files intact." }
& $Loader uninstall
if ($LASTEXITCODE -ne 0) { throw "Uninstall failed." }
