[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$restartStage = 'elevating'
$restartLog = 'D:\04_DATA\ACM TOPS\native_tee_build\firmware-restart-result.json'
try {
# Launch manually after saving work. User authorized reboot for local TEE setup.
# /t 0 without /f avoids force-closing applications; a positive timeout would
# imply /f. This script cannot operate firmware menus for the user.
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -ArgumentList ('-NoProfile -File "' + $PSCommandPath + '"') -Verb RunAs -WindowStyle Hidden | Out-Null
    return
}
# Obtain a fresh elevated status before asking the user to change firmware.
# Do not retrieve recovery keys or disable/suspend volume protection.
$preflightStarted = [DateTime]::UtcNow
$restartStage = 'preflight'
& (Join-Path $PSScriptRoot 'admin_preflight.ps1')
$preflightPath = 'D:\04_DATA\ACM TOPS\native_tee_build\admin-preflight.json'
if (!(Test-Path -LiteralPath $preflightPath) -or
    (Get-Item -LiteralPath $preflightPath).LastWriteTimeUtc -lt $preflightStarted) {
    throw 'No fresh administrator preflight result. No restart performed.'
}
$preflight = Get-Content -Raw -LiteralPath $preflightPath | ConvertFrom-Json
if (!$preflight.preflight_complete -or !$preflight.administrator -or
    $preflight.PSObject.Properties.Name -notcontains 'encryption' -or
    @($preflight.encryption).Count -eq 0 -or @($preflight.encryption | Where-Object {
        $_.EncryptionPercentage -ne 0 -or $_.ProtectionStatus -ne 0
    }).Count) {
    throw 'Firmware restart stopped: volume protection is enabled or could not be verified. See admin-preflight.json.'
}
$restartStage = 'requesting-firmware-restart'
[ordered]@{timestamp_utc=[DateTime]::UtcNow.ToString('o');stage=$restartStage;forced_close=$false} |
    ConvertTo-Json | Set-Content -LiteralPath $restartLog -Encoding UTF8
$shutdownOutput = & "$env:SystemRoot\System32\shutdown.exe" /r /fw /t 0 2>&1
$shutdownCode = $LASTEXITCODE
[ordered]@{timestamp_utc=[DateTime]::UtcNow.ToString('o');stage='shutdown-returned';exit_code=$shutdownCode;output=($shutdownOutput -join "`n");forced_close=$false} |
    ConvertTo-Json | Set-Content -LiteralPath $restartLog -Encoding UTF8
if ($shutdownCode -ne 0) { throw "Firmware restart failed ($shutdownCode): $shutdownOutput" }
} catch {
    [ordered]@{timestamp_utc=[DateTime]::UtcNow.ToString('o');stage=$restartStage;error=$_.Exception.Message;location=$_.InvocationInfo.PositionMessage;forced_close=$false} |
        ConvertTo-Json | Set-Content -LiteralPath $restartLog -Encoding UTF8
    throw
}
