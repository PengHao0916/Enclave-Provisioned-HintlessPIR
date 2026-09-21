[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
# A project-local development identity, stored only in CurrentUser\My.
# Does not trust a new root, export a private key, or change machine boot policy.
$subject = 'CN=HintlessPIR-VBS-Local-Development'
$certs = @(Get-ChildItem Cert:\CurrentUser\My | Where-Object {
    $_.Subject -eq $subject -and $_.HasPrivateKey -and
    $_.NotAfter -gt (Get-Date).AddDays(1)
})
if ($certs.Count -gt 1) { throw 'Multiple project certificates exist; select a thumbprint explicitly.' }
if ($certs.Count -eq 1) {
    $cert = $certs[0]
} else {
    $cert = New-SelfSignedCertificate -CertStoreLocation Cert:\CurrentUser\My `
        -Subject $subject -FriendlyName 'HintlessPIR VBS local development only' `
        -Type Custom -KeyUsage DigitalSignature -KeySpec Signature `
        -KeyLength 3072 -KeyAlgorithm RSA -HashAlgorithm SHA256 `
        -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddDays(90) `
        -TextExtension @(
            '2.5.29.37={text}1.3.6.1.5.5.7.3.3,1.3.6.1.4.1.311.76.57.1.15,1.3.6.1.4.1.311.97.20260918.368.1'
        )
}
Write-Output $cert.Thumbprint
