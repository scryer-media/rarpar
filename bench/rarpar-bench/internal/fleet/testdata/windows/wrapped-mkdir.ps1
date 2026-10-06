$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
try {
New-Item -ItemType Directory -Force -Path 'C:\bench\fleet-stage\fleet-testrun\bin' | Out-Null
} catch {
  [Console]::Error.WriteLine($_.Exception.Message)
  exit 1
}
