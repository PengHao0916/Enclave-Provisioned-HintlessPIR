[CmdletBinding()]
param([string]$OutputDir = 'D:\04_DATA\ACM TOPS\native_tee_build')
$ErrorActionPreference = 'Stop'
$result = [ordered]@{timestamp_utc=[DateTime]::UtcNow.ToString('o'); changes_made=@()}
try {
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    $result.administrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (!$result.administrator) { throw 'Administrator token is required for this read-only preflight.' }
    try { $result.secure_boot = Confirm-SecureBootUEFI } catch { $result.secure_boot_error = $_.Exception.Message }
    try {
        $tpm = Get-Tpm
        $result.tpm = [ordered]@{present=$tpm.TpmPresent;ready=$tpm.TpmReady;enabled=$tpm.TpmEnabled;activated=$tpm.TpmActivated}
    } catch { $result.tpm_error = $_.Exception.Message }
    try {
        # Only status fields; never retrieve recovery passwords or key protectors.
        $result.encryption = @(Get-BitLockerVolume | Select-Object MountPoint,VolumeStatus,ProtectionStatus,EncryptionPercentage,LockStatus)
    } catch { $result.encryption_error = $_.Exception.Message }
    $bcd = & "$env:SystemRoot\System32\bcdedit.exe" /enum 2>&1
    $result.bcd_read_exit_code = $LASTEXITCODE
    $result.bcd_read_output = ($bcd -join "`n")
    $result.preflight_complete = $true
} catch {
    $result.preflight_complete = $false
    $result.error = $_.Exception.Message
} finally {
    $result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $OutputDir 'admin-preflight.json') -Encoding UTF8
}
