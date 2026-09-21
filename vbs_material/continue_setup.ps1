[CmdletBinding()]
param([ValidateSet('Status','Arm','Resume','Cancel')][string]$Action = 'Status')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$buildDir = 'D:\04_DATA\ACM TOPS\native_tee_build'
$sourceDir = Join-Path $buildDir 'source'
$statePath = Join-Path $buildDir 'setup-continuation.json'
$statusPath = Join-Path $buildDir 'setup-status.json'
$runOncePath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
$runOnceName = 'HintlessPIRVbsSetup'
$powershell = 'C:\Program Files\PowerShell\7\pwsh.exe'
if (!(Test-Path -LiteralPath $powershell)) { throw 'The verified PowerShell 7 runtime is required.' }
$resumeCommand = '"' + $powershell + '" -NoProfile -WindowStyle Hidden -File "' +
    (Join-Path $sourceDir 'continue_setup.ps1') + '" -Action Resume'
if ([IO.Path]::GetFullPath($PSScriptRoot) -ne $sourceDir) {
    throw 'Run the staged local script in native_tee_build\source.'
}
. (Join-Path $sourceDir 'setup_policy.ps1')

function Read-Environment {
    if (!('HintlessVbsSetup.CodeIntegrity' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
namespace HintlessVbsSetup {
    public static class CodeIntegrity {
        [StructLayout(LayoutKind.Sequential)]
        public struct Info { public uint Length; public uint Options; }
        [DllImport("ntdll.dll")]
        private static extern int NtQuerySystemInformation(int kind, ref Info data, int size, out int returned);
        public static uint ReadOptions() {
            Info info = new Info { Length = 8 }; int returned;
            int status = NtQuerySystemInformation(103, ref info, 8, out returned);
            if (status < 0 || returned != 8) throw new InvalidOperationException("Cannot read active code integrity options.");
            return info.Options;
        }
    }
}
'@
    }
    $result = [ordered]@{secure_boot=$null; test_signing_active=$null; hvci_running=$null; errors=@()}
    try {
        $value = Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -Name UEFISecureBootEnabled
        if ($value -notin @(0,1)) { throw 'Unexpected Secure Boot value.' }
        $result.secure_boot = $value -eq 1
    } catch { $result.errors += $_.Exception.Message }
    try {
        $options = [HintlessVbsSetup.CodeIntegrity]::ReadOptions()
        $result.test_signing_active = ($options -band 2) -ne 0
        $result.code_integrity_options = $options
    } catch { $result.errors += $_.Exception.Message }
    try {
        $guard = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard
        $result.hvci_running = $guard.VirtualizationBasedSecurityStatus -eq 2 -and $guard.SecurityServicesRunning -contains 2
    } catch { $result.errors += $_.Exception.Message }
    return [pscustomobject]$result
}
function Set-ResumeEntry {
    New-Item -Path $runOncePath -Force | Out-Null
    $old = Get-ItemProperty -LiteralPath $runOncePath -Name $runOnceName -ErrorAction SilentlyContinue
    if ($old -and $old.$runOnceName -ne $resumeCommand) { throw 'A different RunOnce entry uses this name.' }
    New-ItemProperty -LiteralPath $runOncePath -Name $runOnceName -Value $resumeCommand -PropertyType String -Force | Out-Null
}
function Remove-ResumeEntry {
    $old = Get-ItemProperty -LiteralPath $runOncePath -Name $runOnceName -ErrorAction SilentlyContinue
    if ($old -and $old.$runOnceName -eq $resumeCommand) {
        Remove-ItemProperty -LiteralPath $runOncePath -Name $runOnceName
    }
}
function Notify-User([string]$Message) {
    # A visible message is needed after a login-triggered run. It never accepts
    # secrets or causes a restart. The helper process itself stays hidden.
    if ($Action -eq 'Resume') {
        Add-Type -AssemblyName System.Windows.Forms
        [Windows.Forms.MessageBox]::Show($Message, 'HintlessPIR local VBS setup', 'OK', 'Information') | Out-Null
    }
}
function Write-Status([string]$Phase, [string]$Message, $Environment) {
    $status = [ordered]@{
        timestamp_utc=[DateTime]::UtcNow.ToString('o'); phase=$Phase; message=$Message
        environment=$Environment; private_backend_complete=$false; automatic_reboot=$false
    }
    $status | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $statusPath -Encoding UTF8
    $status | ConvertTo-Json -Depth 5 | Write-Output
}
function Pinned-Files {
    @('source\continue_setup.ps1','source\setup_policy.ps1','source\after_firmware.ps1',
      'source\enable_test_signing.ps1','source\run_probe.ps1','source\validate_lifecycle.ps1',
      'hintless_vbs_probe.dll','probe_host.exe','channel_test_host.exe')
}
function Invoke-Step([string]$Script, [string]$Extra, [string]$LogName) {
    $outputLog = Join-Path $buildDir ($LogName + '.stdout.log')
    $errorLog = Join-Path $buildDir ($LogName + '.stderr.log')
    $arguments = '-NoProfile -File "' + (Join-Path $sourceDir $Script) + '" ' + $Extra
    $process = Start-Process -FilePath $powershell -ArgumentList $arguments -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput $outputLog -RedirectStandardError $errorLog
    # Retain a real process handle before waiting. Windows PowerShell's
    # Start-Process wrapper can otherwise return a null ExitCode after exit.
    $retainedHandle = $process.Handle
    if (!$process.WaitForExit(300000)) {
        # Stop only this helper, never Windows, WSL, or unrelated applications.
        Stop-Process -Id $process.Id -ErrorAction SilentlyContinue
        throw "Step timed out: $Script. Inspect $errorLog."
    }
    $exitCode = $process.ExitCode
    if ($null -eq $exitCode -or $exitCode -ne 0) { throw "Step failed: $Script. Inspect $errorLog." }
}

try {
    if ($Action -eq 'Cancel') {
        Remove-ResumeEntry
        if (Test-Path -LiteralPath $statePath) { Remove-Item -LiteralPath $statePath }
        Write-Status 'cancelled' 'One-time continuation removed. Boot settings were not changed.' $null
        return
    }
    $environment = Read-Environment
    if ($Action -eq 'Arm') {
        $hashes = [ordered]@{}
        foreach ($name in (Pinned-Files)) {
            $hashes[$name] = (Get-FileHash -LiteralPath (Join-Path $buildDir $name)).Hash
        }
        [ordered]@{
            schema=1; expires_utc=[DateTime]::UtcNow.AddDays(7).ToString('o')
            source_sha256=$hashes; signing_attempted=$false
        } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $statePath -Encoding UTF8
        Set-ResumeEntry
        Write-Status 'armed' 'One-time continuation registered for your next Windows login. No restart or boot change was performed.' $environment
        return
    }
    if ($Action -eq 'Status') {
        $next = Get-VbsSetupAction $environment.secure_boot $environment.test_signing_active $environment.hvci_running
        Write-Status $next 'Read-only inspection. Resume requires an explicit Arm checkpoint.' $environment
        return
    }
    # RunOnce is normally deleted by Windows before launch. Remove our exact
    # value as well when Resume is invoked manually; never leave a polling loop.
    Remove-ResumeEntry
    if (!(Test-Path -LiteralPath $statePath)) { throw 'No armed setup checkpoint exists.' }
    $state = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
    $match = $true
    foreach ($name in (Pinned-Files)) {
        $property = $state.source_sha256.PSObject.Properties[$name]
        if (!$property -or (Get-FileHash -LiteralPath (Join-Path $buildDir $name)).Hash -ne $property.Value) { $match = $false }
    }
    $next = Get-VbsSetupAction $environment.secure_boot $environment.test_signing_active $environment.hvci_running `
        -Expired ([DateTime]::UtcNow -gt [DateTime]::Parse($state.expires_utc).ToUniversalTime()) -FilesMatch $match
    if ($next -eq 'enable-test-signing') {
        if ($state.signing_attempted) {
            Write-Status 'signing-not-active' 'A prior signing change has not become active. Stop here for diagnosis; no automatic loop.' $environment
            Notify-User 'Test signing is still inactive. Open native_tee_build\setup-status.json and return to Codex; no further changes were made.'
            return
        }
        # Existing elevated helper checks Secure Boot and volume protection,
        # changes only TESTSIGNING, and writes a fresh machine-readable result.
        Invoke-Step 'after_firmware.ps1' '' 'setup-enable-signing'
        $state.signing_attempted = $true
        $state | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $statePath -Encoding UTF8
        Set-ResumeEntry
        Write-Status 'restart-required' 'TESTSIGNING change accepted. Save work and restart Windows normally. Validation resumes after login.' $environment
        Notify-User 'TESTSIGNING was enabled. Save your work and restart Windows normally. Enclave validation will run automatically after your next login. This helper will not restart your computer.'
        return
    }
    if ($next -eq 'run-enclave-validation') {
        Write-Status 'validating' 'Running real enclave probe and public-fixture lifecycle checks. No native fallback.' $environment
        Invoke-Step 'run_probe.ps1' ('-BuildDir "' + $buildDir + '"') 'setup-enclave-probe'
        $probe = Get-Content -Raw -LiteralPath (Join-Path $buildDir 'probe-result.json') | ConvertFrom-Json
        if (!$probe.probe_validated -or !$probe.enclave_called -or $probe.enclave_crypto_checks_passed -ne 68) {
            throw 'Probe did not confirm actual enclave execution and all 68 enclave checks.'
        }
        Invoke-Step 'validate_lifecycle.ps1' '-Backend enclave' 'setup-enclave-lifecycle'
        foreach ($profile in @('functional','8mb')) {
            $result = Get-Content -Raw -LiteralPath (Join-Path $buildDir "interop-lifecycle-enclave-$profile.json") | ConvertFrom-Json
            if ($result.correct_queries -ne 3 -or !$result.authenticated_installation_and_journal) { throw 'Incomplete enclave lifecycle results.' }
        }
        Write-Status 'enclave-public-tests-passed' 'Real enclave execution and six public-fixture queries passed. Private client attestation remains incomplete.' $environment
        Notify-User 'Real enclave public-fixture checks passed. Results are in native_tee_build. Return to Codex for the remaining private-client attestation work.'
        return
    }
    Write-Status $next 'Stopped without system changes. See the phase and environment fields; no automatic retry was registered.' $environment
    Notify-User ('VBS setup stopped: ' + $next + '. See native_tee_build\setup-status.json. If Secure Boot is still on, change that setting in BIOS and then run the desktop continuation shortcut.')
} catch {
    Write-Status 'failed' $_.Exception.Message $null
    Notify-User ('VBS setup stopped: ' + $_.Exception.Message)
    exit 1
}
