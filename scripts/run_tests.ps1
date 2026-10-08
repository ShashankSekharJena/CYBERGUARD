$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot

Push-Location $projectRoot
try {
    python -m unittest discover -s backend/tests
}
finally {
    Pop-Location
}
