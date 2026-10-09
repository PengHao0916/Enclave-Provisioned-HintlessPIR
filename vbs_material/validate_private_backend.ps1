[CmdletBinding()]
param(
    [ValidateRange(1,100)][int]$Runs = 10,
    [string]$BuildDir = 'D:\04_DATA\ACM TOPS\native_tee_build'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($BuildDir -ne 'D:\04_DATA\ACM TOPS\native_tee_build') {
    throw 'This launcher is scoped to the verified local build directory.'
}
$exe = Join-Path $BuildDir 'channel_test_host.exe'
$dll = Join-Path $BuildDir 'hintless_vbs_probe.dll'
foreach ($required in @($exe, $dll)) {
    if (!(Test-Path -LiteralPath $required)) { throw "Missing required binary: $required" }
}

function Get-TimingSummary([object[]]$Cases, [string]$Property) {
    [double[]]$values = @($Cases | ForEach-Object { [double]($_.$Property) / 1000000.0 } | Sort-Object)
    if (!$values.Count) { throw "No samples for $Property" }
    $mean = ($values | Measure-Object -Average).Average
    $sumSquares = 0.0
    foreach ($value in $values) { $sumSquares += [Math]::Pow($value - $mean, 2) }
    $stddev = if ($values.Count -gt 1) { [Math]::Sqrt($sumSquares / ($values.Count - 1)) } else { 0.0 }
    $middle = [int][Math]::Floor($values.Count / 2)
    $median = if ($values.Count % 2) { $values[$middle] } else { ($values[$middle - 1] + $values[$middle]) / 2.0 }
    [int]$p95Index = [Math]::Max(0, [Math]::Ceiling(0.95 * $values.Count) - 1)
    [ordered]@{
        samples = $values.Count
        mean_ms = [Math]::Round($mean, 4)
        median_ms = [Math]::Round($median, 4)
        stddev_ms = [Math]::Round($stddev, 4)
        p95_ms = [Math]::Round($values[$p95Index], 4)
        min_ms = [Math]::Round($values[0], 4)
        max_ms = [Math]::Round($values[-1], 4)
    }
}

$profileResults = @()
foreach ($profile in @('functional','8mb')) {
    $cases = @()
    for ($run = 1; $run -le $Runs; ++$run) {
        $outputDir = "/mnt/d/04_DATA/ACM TOPS/native_tee_build/interop-private-$profile-$run"
        $log = Join-Path $BuildDir "interop-private-$profile-$run.log"
        $arguments = @('run','-c','opt','--jobs=4','//vbs_material:material_interop_test','--',
            'enclave-private-lifecycle',$profile,'/mnt/d/04_DATA/ACM TOPS/native_tee_build/channel_test_host.exe',
            $outputDir,$dll)
        $text = & wsl.exe -d Ubuntu --cd /home/ph/single-server-pir -- /home/ph/bin/bazel @arguments 2> $log
        if ($LASTEXITCODE -ne 0) { throw "Private VBS run failed; inspect $log." }
        $result = ($text -join "`n") | ConvertFrom-Json
        if ($result.backend -ne 'vbs-enclave-private-seed-research' -or
            $result.public_test_secrets_only -ne $false -or
            $result.private_seed_channel_executed -ne $true -or
            $result.real_attestation_verified -ne $false -or
            $result.authenticated_installation_and_journal -ne $true -or
            $result.correct_queries -ne 3 -or @($result.cases | Where-Object {
                !$_.record_correct -or !$_.all_rlwe_noise_relations_checked -or
                !$_.retry_checked -or !$_.reuse_rejected -or
                $_.enclave_load_ns -le 0 -or $_.enclave_generate_ns -le 0 -or
                $_.material_lifecycle_total_ns -le 0 -or $_.server_handle_ns -le 0
            }).Count) {
            throw "Incomplete private VBS evidence for $profile run $run."
        }
        foreach ($case in $result.cases) {
            $case | Add-Member -NotePropertyName run -NotePropertyValue $run
            $cases += $case
        }
    }
    $timings = [ordered]@{}
    foreach ($property in @('enclave_load_ns','channel_begin_ns','client_seal_ns',
            'enclave_generate_ns','receipt_accept_ns','installation_roundtrip_ns',
            'material_lifecycle_total_ns','query_generation_ns','server_handle_ns',
            'recovery_ns','online_total_ns')) {
        $timings[$property.Replace('_ns','')] = Get-TimingSummary $cases $property
    }
    $profileResults += [ordered]@{
        profile = $profile
        runs = $Runs
        correct_queries = $cases.Count
        all_records_correct = $true
        all_noise_relations_checked = $true
        all_retries_exact = $true
        all_reuse_attempts_rejected = $true
        timing = $timings
        cases = $cases
    }
}

$evidence = [ordered]@{
    schema = 1
    timestamp_utc = [DateTime]::UtcNow.ToString('o')
    backend = 'windows-vbs-enclave-private-seed-research'
    research_prototype_only = $true
    public_test_secrets_only = $false
    private_seed_channel_executed = $true
    private_material_backend_implemented = $true
    attestation_scope = 'local-report-binding-only'
    real_attestation_verified = $false
    client_server_process_isolation = $false
    encrypted_seed_bytes = 48
    client_master_seed_bytes = 32
    enclave_binary_sha256 = (Get-FileHash -LiteralPath $dll).Hash
    client_helper_sha256 = (Get-FileHash -LiteralPath $exe).Hash
    profiles = $profileResults
}
$path = Join-Path $BuildDir 'private-vbs-research-results.json'
$evidence | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding UTF8
$evidence | ConvertTo-Json -Depth 10
