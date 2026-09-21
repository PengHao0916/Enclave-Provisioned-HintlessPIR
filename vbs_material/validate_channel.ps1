[CmdletBinding()]
param(
    [ValidateSet('native','enclave')][string]$Backend = 'native',
    [string]$BuildDir = 'D:\04_DATA\ACM TOPS\native_tee_build'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($BuildDir -ne 'D:\04_DATA\ACM TOPS\native_tee_build') {
    throw 'This launcher is scoped to the verified local build directory.'
}
$exe = Join-Path $BuildDir 'channel_test_host.exe'
$binaryHash = (Get-FileHash -LiteralPath $exe).Hash
# The native test host accepts only fixed PUBLIC fixtures. It cannot certify a
# platform and supplies no production attestation-verification implementation.
$results = @()
foreach ($profile in @('functional','8mb')) {
    $log = Join-Path $BuildDir "interop-channel-$Backend-$profile.log"
    $arguments = @('run','-c','opt','--jobs=4','//vbs_material:material_interop_test','--',
        $Backend,$profile,'/mnt/d/04_DATA/ACM TOPS/native_tee_build/channel_test_host.exe',
        "/mnt/d/04_DATA/ACM TOPS/native_tee_build/interop-channel-$Backend")
    if ($Backend -eq 'enclave') { $arguments += (Join-Path $BuildDir 'hintless_vbs_probe.dll') }
    $text = & wsl.exe -d Ubuntu --cd /home/ph/single-server-pir -- /home/ph/bin/bazel @arguments 2> $log
    if ($LASTEXITCODE -ne 0) { throw "Encrypted-channel interop failed; inspect $log." }
    $result = ($text -join "`n") | ConvertFrom-Json
    if ($result.correct_queries -ne 3 -or @($result.cases | Where-Object {
        !$_.record_correct -or !$_.all_rlwe_noise_relations_checked -or !$_.retry_checked -or !$_.reuse_rejected
    }).Count) { throw "Incomplete interop checks for $profile" }
    $result.backend = $(if($Backend -eq 'native'){'windows-native-encrypted-channel-NOT-TEE'}else{'vbs-encrypted-material-public-test'})
    $result | Add-Member -NotePropertyName real_attestation_verified -NotePropertyValue $false
    $result | Add-Member -NotePropertyName generation_receipt_verified -NotePropertyValue $true
    $result | Add-Member -NotePropertyName timestamp_utc -NotePropertyValue ([DateTime]::UtcNow.ToString('o'))
    $result | Add-Member -NotePropertyName test_binary_sha256 -NotePropertyValue $binaryHash
    $result | Add-Member -NotePropertyName enclave_binary_sha256 -NotePropertyValue $(if($Backend -eq 'enclave'){(Get-FileHash -LiteralPath (Join-Path $BuildDir 'hintless_vbs_probe.dll')).Hash}else{$null})
    $result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $BuildDir "interop-channel-$Backend-$profile.json") -Encoding UTF8
    $results += $result
}
$results | ConvertTo-Json -Depth 5
