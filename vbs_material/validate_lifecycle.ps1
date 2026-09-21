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
$results = @()
foreach ($profile in @('functional','8mb')) {
    $log = Join-Path $BuildDir "interop-lifecycle-$Backend-$profile.log"
    $arguments = @('run','-c','opt','--jobs=4','//vbs_material:material_interop_test','--',
        "$Backend-lifecycle",$profile,'/mnt/d/04_DATA/ACM TOPS/native_tee_build/channel_test_host.exe',
        "/mnt/d/04_DATA/ACM TOPS/native_tee_build/interop-lifecycle-$Backend")
    if ($Backend -eq 'enclave') { $arguments += (Join-Path $BuildDir 'hintless_vbs_probe.dll') }
    $text = & wsl.exe -d Ubuntu --cd /home/ph/single-server-pir -- /home/ph/bin/bazel @arguments 2> $log
    if ($LASTEXITCODE -ne 0) { throw "Lifecycle interop failed; inspect $log and per-case backend logs." }
    $result = ($text -join "`n") | ConvertFrom-Json
    if ($result.correct_queries -ne 3 -or !$result.authenticated_installation_and_journal -or
        $result.installation_negative_cases -ne 4 -or @($result.cases | Where-Object {
        !$_.record_correct -or !$_.all_rlwe_noise_relations_checked -or !$_.retry_checked -or !$_.reuse_rejected
    }).Count) { throw "Incomplete lifecycle checks for $profile" }
    $result.backend = $(if($Backend -eq 'native'){'windows-native-material-lifecycle-NOT-TEE'}else{'vbs-material-lifecycle-public-test'})
    $result | Add-Member -NotePropertyName timestamp_utc -NotePropertyValue ([DateTime]::UtcNow.ToString('o'))
    $result | Add-Member -NotePropertyName test_binary_sha256 -NotePropertyValue $binaryHash
    $result | Add-Member -NotePropertyName enclave_binary_sha256 -NotePropertyValue $(if($Backend -eq 'enclave'){(Get-FileHash -LiteralPath (Join-Path $BuildDir 'hintless_vbs_probe.dll')).Hash}else{$null})
    $result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $BuildDir "interop-lifecycle-$Backend-$profile.json") -Encoding UTF8
    $results += $result
}
$results | ConvertTo-Json -Depth 5
