# release.yml, build-windows: "Confirm the 8 MiB stack reserve".
# Reads SizeOfStackReserve from the PE optional header: e_lfanew at 0x3C
# points at the "PE\0\0" signature, the optional header starts 24 bytes after
# it, and the field sits 72 bytes into that header, 4 bytes wide in PE32 and
# 8 in PE32+. MSVC links default to 1 MiB; configure-build-environment.ps1
# asks for 8 MiB.
$ErrorActionPreference = "Stop"
$expected = 8388608
$exe = Join-Path $env:RARPAR_RELEASE_TARGET_DIR "${env:RELEASE_TARGET}\release\rarpar.exe"
$bytes = [System.IO.File]::ReadAllBytes($exe)
$pe = [BitConverter]::ToInt32($bytes, 0x3C)
if ([BitConverter]::ToUInt32($bytes, $pe) -ne 0x00004550) {
  throw "$exe has no PE signature"
}
$optional = $pe + 24
$magic = [BitConverter]::ToUInt16($bytes, $optional)
switch ($magic) {
  0x10B { $reserve = [BitConverter]::ToUInt32($bytes, $optional + 72) }
  0x20B { $reserve = [BitConverter]::ToUInt64($bytes, $optional + 72) }
  default { throw ("{0} has an unknown optional header magic 0x{1:X}" -f $exe, $magic) }
}
if ($reserve -ne $expected) {
  throw "$exe reserves $reserve bytes of main-thread stack, expected $expected"
}
Write-Host "$exe reserves $reserve bytes of main-thread stack"
