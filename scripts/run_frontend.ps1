$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot

npm --prefix (Join-Path $projectRoot "frontend") run dev
