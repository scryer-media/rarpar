# ci.yml, platform-tests-windows and target-checks-windows: "Install NASM". The
# matrix `nasm` field says which rows need it; the others run this step and
# install nothing.
$ErrorActionPreference = "Stop"
if ($env:NEEDS_NASM -ne "true") {
  Write-Host "this matrix row builds without NASM"
  return
}
$url = "https://www.nasm.us/pub/nasm/releasebuilds/3.01/win64/nasm-3.01-win64.zip"
$expectedSha256 = "e0ba5157007abc7b1a65118a96657a961ddf55f7e3f632ee035366dfce039ca4"
Invoke-WebRequest $url -OutFile nasm.zip
$actualSha256 = (Get-FileHash nasm.zip -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualSha256 -ne $expectedSha256) {
  throw "NASM checksum mismatch: expected $expectedSha256, got $actualSha256"
}
Expand-Archive nasm.zip -DestinationPath C:\nasm
$dir = (Get-ChildItem C:\nasm -Directory | Select-Object -First 1).FullName
$dir | Out-File -Append -Encoding utf8 $env:GITHUB_PATH
