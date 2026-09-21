$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'setup_policy.ps1')
$cases = @(
    @{sb=$true; ts=$false; hv=$true; want='firmware-required'},
    @{sb=$false; ts=$false; hv=$true; want='enable-test-signing'},
    @{sb=$false; ts=$true; hv=$true; want='run-enclave-validation'},
    @{sb=$false; ts=$true; hv=$false; want='hvci-required'},
    @{sb=$null; ts=$true; hv=$true; want='unknown-secure-boot'},
    @{sb=$false; ts=$null; hv=$true; want='unknown-signing-state'},
    @{sb=$false; ts=$true; hv=$null; want='unknown-hvci-state'}
)
foreach ($case in $cases) {
    $actual = Get-VbsSetupAction $case.sb $case.ts $case.hv
    if ($actual -ne $case.want) { throw "Expected $($case.want), got $actual" }
}
if ((Get-VbsSetupAction $false $true $true -Expired $true) -ne 'expired') { throw 'Expired checkpoints must stop.' }
if ((Get-VbsSetupAction $false $true $true -FilesMatch $false) -ne 'files-changed') { throw 'Changed artifacts must stop.' }
[ordered]@{success=$true; tests_passed=9; system_changes=$false} | ConvertTo-Json
