$os = Get-CimInstance Win32_OperatingSystem
$load = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
Write-Output ("{0} {1} {2}" -f $os.Caption, $os.Version, $env:PROCESSOR_ARCHITECTURE)
Write-Output ("nproc={0}" -f $env:NUMBER_OF_PROCESSORS)
Write-Output ("cpu_load_percent={0}" -f $load)