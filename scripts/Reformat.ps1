[CmdletBinding()]
param([switch]$Check)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$formatter = Get-Command clang-format -ErrorAction Stop
$failed = $false

# Format first-party source only: never build caches, package downloads, or
# vendored headers. Resolve from the script, not the caller's working directory.
foreach ($directory in @("src", "tests")) {
    $files = Get-ChildItem -LiteralPath (Join-Path $root $directory) -Recurse -File |
        Where-Object { $_.Extension -in @(".c", ".cpp", ".h", ".hpp", ".cc") }
    foreach ($file in $files) {
        if ($Check) {
            & $formatter.Source --dry-run --Werror $file.FullName
        } else {
            & $formatter.Source -i $file.FullName
        }
        if ($LASTEXITCODE -ne 0) { $failed = $true }
    }
}
if ($failed) { throw "clang-format failed; see diagnostics above." }
