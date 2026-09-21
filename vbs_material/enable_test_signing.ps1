#Requires -RunAsAdministrator
[CmdletBinding()]
param([string]$OutputDir = 'D:\04_DATA\ACM TOPS\native_tee_build')
$ErrorActionPreference = 'Stop'
$result = [ordered]@{timestamp_utc=[DateTime]::UtcNow.ToString('o');requested_change='TESTSIGNING ON';reboot_performed=$false}
try {
    # User explicitly authorized local test-signing setup on 2026-09-18.
    # This script never changes Secure Boot, encryption, HVCI, or integrity flags.
    $result.secure_boot = Confirm-SecureBootUEFI
    $volumes = @(Get-BitLockerVolume)
    $result.encryption = @($volumes | Select-Object MountPoint,VolumeStatus,ProtectionStatus,EncryptionPercentage)
    if (@($volumes | Where-Object { $_.MountPoint -eq $env:SystemDrive -and [int]$_.ProtectionStatus -ne 0 }).Count) {
        throw 'OS drive encryption protection is active. Confirm recovery arrangements before changing boot configuration.'
    }
    $output = & "$env:SystemRoot\System32\bcdedit.exe" /set TESTSIGNING ON 2>&1
    $result.bcd_exit_code = $LASTEXITCODE
    $result.bcd_output = ($output -join "`n")
    $result.change_applied = ($LASTEXITCODE -eq 0)
    $result.reboot_required = $result.change_applied
    if (!$result.change_applied -and $result.secure_boot) {
        $result.next_action = 'Disable Secure Boot in firmware, then rerun this script. Keep Memory Integrity enabled.'
    }
} catch {
    $result.change_applied = $false
    $result.error = $_.Exception.Message
} finally {
    $result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $OutputDir 'test-signing-change.json') -Encoding UTF8
}
