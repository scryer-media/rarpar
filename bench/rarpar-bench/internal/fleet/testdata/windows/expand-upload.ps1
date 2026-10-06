New-Item -ItemType Directory -Force -Path 'C:\bench\fleet-stage\fleet-testrun\bin' | Out-Null
Expand-Archive -LiteralPath 'C:\bench\fleet-stage\fleet-testrun\bin\fleet-upload.zip' -DestinationPath 'C:\bench\fleet-stage\fleet-testrun\bin' -Force
Remove-Item -LiteralPath 'C:\bench\fleet-stage\fleet-testrun\bin\fleet-upload.zip' -Force