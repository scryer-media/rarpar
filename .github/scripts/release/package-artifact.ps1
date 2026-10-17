# release.yml, build-windows: "Package artifact".
$ErrorActionPreference = "Stop"
$archive = "rarpar-${env:RELEASE_TAG}-${env:RELEASE_PLATFORM}.${env:RELEASE_ARCHIVE_EXT}"
Remove-Item -Recurse -Force package -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force package, dist | Out-Null
Copy-Item (Join-Path $env:RARPAR_RELEASE_TARGET_DIR "${env:RELEASE_TARGET}\release\rarpar.exe") package\
Copy-Item README.md package\
Copy-Item tools\rarpar\LICENSE package\LICENSE
Copy-Item target\dist\docs\share package\share -Recurse
Compress-Archive -Path package\* -DestinationPath $archive
Move-Item $archive dist\
