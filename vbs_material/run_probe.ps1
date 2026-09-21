[CmdletBinding()]
param([string]$BuildDir = (Join-Path $env:LOCALAPPDATA 'HintlessPIR\vbs-build'))
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$exe = Join-Path $BuildDir 'probe_host.exe'
$dll = Join-Path $BuildDir 'hintless_vbs_probe.dll'
$report = Join-Path $BuildDir 'attestation-report.bin'
$output = & $exe $dll $report
$probeExitCode = $LASTEXITCODE
$probe = ($output -join "`n") | ConvertFrom-Json
$probe | Add-Member -NotePropertyName process_exit_code -NotePropertyValue $probeExitCode
$probe | Add-Member -NotePropertyName timestamp_utc -NotePropertyValue ([DateTime]::UtcNow.ToString('o'))
$probe | Add-Member -NotePropertyName tested_enclave_sha256 -NotePropertyValue ((Get-FileHash -LiteralPath $dll -Algorithm SHA256).Hash)
$probe | Add-Member -NotePropertyName tested_host_sha256 -NotePropertyValue ((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash)
$probe | Add-Member -NotePropertyName win32_error_message -NotePropertyValue ((New-Object ComponentModel.Win32Exception([int]$probe.win32_error)).Message)
$json = $probe | ConvertTo-Json -Depth 4
$json | Set-Content -LiteralPath (Join-Path $BuildDir 'probe-result.json') -Encoding UTF8
Write-Output $json
if ($probeExitCode -ne 0) { exit $probeExitCode }
