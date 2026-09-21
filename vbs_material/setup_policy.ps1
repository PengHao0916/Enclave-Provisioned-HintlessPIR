# Pure decision logic: importing this file makes no system changes.
function Get-VbsSetupAction {
    param(
        [AllowNull()]$SecureBoot,
        [AllowNull()]$TestSigningActive,
        [AllowNull()]$HvciRunning,
        [bool]$Expired = $false,
        [bool]$FilesMatch = $true
    )
    if ($Expired) { return 'expired' }
    if (!$FilesMatch) { return 'files-changed' }
    if ($null -eq $SecureBoot) { return 'unknown-secure-boot' }
    if ($SecureBoot -eq $true) { return 'firmware-required' }
    if ($null -eq $TestSigningActive) { return 'unknown-signing-state' }
    if ($TestSigningActive -eq $false) { return 'enable-test-signing' }
    if ($null -eq $HvciRunning) { return 'unknown-hvci-state' }
    if ($HvciRunning -eq $false) { return 'hvci-required' }
    return 'run-enclave-validation'
}
