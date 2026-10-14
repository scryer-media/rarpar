# release.yml, build-windows: "Exclude build dir from Windows Defender".
$ErrorActionPreference = "Stop"
try {
  Add-MpPreference -ExclusionPath "$env:GITHUB_WORKSPACE" -ErrorAction Stop
} catch {
  Write-Warning "Unable to configure Windows Defender exclusion: $($_.Exception.Message)"
}
