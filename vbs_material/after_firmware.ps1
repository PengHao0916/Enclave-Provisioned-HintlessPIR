[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$dir = 'D:\04_DATA\ACM TOPS\native_tee_build'
if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State').UEFISecureBootEnabled -ne 0) {
    throw 'Secure Boot is still enabled. Disable it in firmware first; keep TPM and virtualization enabled.'
}
$started = [DateTime]::UtcNow
$p = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
    -ArgumentList '-NoProfile -File "D:\04_DATA\ACM TOPS\native_tee_build\source\enable_test_signing.ps1"' `
    -Verb RunAs -WindowStyle Hidden -PassThru
$p.WaitForExit()
$log = Join-Path $dir 'test-signing-change.json'
if (!(Test-Path -LiteralPath $log) -or (Get-Item -LiteralPath $log).LastWriteTimeUtc -lt $started) {
    throw 'No fresh test-signing result was written. Check the elevated process; an old result is not sufficient.'
}
$result = Get-Content -Raw -LiteralPath $log | ConvertFrom-Json
if (!$result.change_applied) { throw 'Test signing was not enabled. Inspect test-signing-change.json.' }
Write-Output 'TESTSIGNING ON was accepted. Restart Windows to activate it, keeping Memory Integrity enabled.'
Write-Output ('After restart: & "' + $dir + '\source\run_probe.ps1" -BuildDir "' + $dir + '"')
Write-Output ('Then: & "' + $dir + '\source\validate_interop.ps1" -Backend enclave')
