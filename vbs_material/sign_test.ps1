[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$CertificateThumbprint,
    [string]$BuildDir = (Join-Path $env:LOCALAPPDATA 'HintlessPIR\vbs-build'),
    [string]$SdkVersion = '10.0.26100.0'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$CertificateThumbprint = $CertificateThumbprint.Replace(' ', '')
if ($CertificateThumbprint -notmatch '^[0-9A-Fa-f]{40}$') { throw 'Invalid certificate thumbprint.' }
$cert = Get-Item -LiteralPath "Cert:\CurrentUser\My\$CertificateThumbprint"
$eku = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' }
$oids = @($eku.EnhancedKeyUsages | ForEach-Object { $_.Value })
if (!$cert.HasPrivateKey -or $oids -notcontains '1.3.6.1.5.5.7.3.3' -or
    $oids -notcontains '1.3.6.1.4.1.311.76.57.1.15' -or
    !($oids | Where-Object { $_ -match '^1\.3\.6\.1\.4\.1\.311\.97\.(\d+)(\.|$)' -and [long]$Matches[1] -gt 999 })) {
    throw 'Certificate must have a private key and code-signing, enclave, and author EKUs.'
}
$kits = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots').KitsRoot10
$signTool = Join-Path $kits "bin\$SdkVersion\x64\signtool.exe"
$dll = Join-Path $BuildDir 'hintless_vbs_probe.dll'
# Signing changes only this DLL. No boot changes, root-store changes, or export
# of private keys. A self-signed certificate still requires test-signing mode.
& $signTool sign /ph /fd SHA256 /sha1 $CertificateThumbprint /s My $dll
$signExitCode = $LASTEXITCODE
# SignTool documents 2 as completion with warnings (e.g. OS support notice).
if ($signExitCode -notin @(0, 2)) { throw "Page-hash signing failed: $signExitCode" }
$signature = Get-AuthenticodeSignature -LiteralPath $dll
if (!$signature.SignerCertificate -or
    $signature.SignerCertificate.Thumbprint -ne $CertificateThumbprint) {
    throw 'Signed DLL does not contain the selected signing certificate.'
}
[ordered]@{
    timestamp_utc = [DateTime]::UtcNow.ToString('o')
    certificate_thumbprint = $CertificateThumbprint
    enclave_sha256 = (Get-FileHash -LiteralPath $dll -Algorithm SHA256).Hash
    page_hash_signing_requested = $true
    signtool_exit_code = $signExitCode
    authenticode_status = $signature.Status.ToString()
    test_signing_boot_mode_changed = $false
} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $BuildDir 'signing-manifest.json') -Encoding UTF8
