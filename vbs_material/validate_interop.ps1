[CmdletBinding()]
param(
    [ValidateSet('native','enclave')][string]$Backend = 'native',
    [string]$BuildDir = 'D:\04_DATA\ACM TOPS\native_tee_build'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
# This workstation uses the WSL checkout and an output directory on D:.
# No eval or shell interpolation of caller-supplied paths.
if ($BuildDir -ne 'D:\04_DATA\ACM TOPS\native_tee_build') {
    throw 'This integration launcher is scoped to the verified workstation build directory.'
}
$results = @()
foreach ($profile in @('functional','8mb')) {
    $out = Join-Path $BuildDir "interop-$Backend-$profile.json"
    $log = Join-Path $BuildDir "interop-$Backend-$profile.log"
    $arguments = @('run','-c','opt','--jobs=4','//vbs_material:material_interop_test','--',
        $Backend,$profile,'/mnt/d/04_DATA/ACM TOPS/native_tee_build/material_test_host.exe',
        "/mnt/d/04_DATA/ACM TOPS/native_tee_build/interop-$Backend")
    if ($Backend -eq 'enclave') { $arguments += (Join-Path $BuildDir 'hintless_vbs_probe.dll') }
    # wsl --cd avoids a shell. Each path remains a separate argv element.
    $text = & wsl.exe -d Ubuntu --cd /home/ph/single-server-pir -- /home/ph/bin/bazel @arguments 2> $log
    if ($LASTEXITCODE -ne 0) { throw "Interop failed; inspect $log. No backend fallback was attempted." }
    $result = ($text -join "`n") | ConvertFrom-Json
    if ($result.correct_queries -ne 3 -or
        @($result.cases | Where-Object { !$_.record_correct -or !$_.all_rlwe_noise_relations_checked -or !$_.reuse_rejected }).Count) {
        throw "Incomplete interop checks for $profile"
    }
    $result | Add-Member -NotePropertyName timestamp_utc -NotePropertyValue ([DateTime]::UtcNow.ToString('o'))
    $result | Add-Member -NotePropertyName native_binary_sha256 -NotePropertyValue ((Get-FileHash -LiteralPath (Join-Path $BuildDir 'material_test_host.exe')).Hash)
    $result | Add-Member -NotePropertyName enclave_binary_sha256 -NotePropertyValue $(if($Backend -eq 'enclave'){(Get-FileHash -LiteralPath (Join-Path $BuildDir 'hintless_vbs_probe.dll')).Hash}else{$null})
    $result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $out -Encoding UTF8
    $results += $result
}
$results | ConvertTo-Json -Depth 5
