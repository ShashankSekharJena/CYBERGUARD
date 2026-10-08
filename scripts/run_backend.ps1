$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot

Push-Location (Join-Path $projectRoot "backend")
try {
    python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
}
finally {
    Pop-Location
}
