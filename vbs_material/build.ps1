[CmdletBinding()]
param(
    [string]$OutDir = (Join-Path $env:LOCALAPPDATA 'HintlessPIR\vbs-build'),
    [string]$SdkVersion = '10.0.26100.0'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$vsRoot = (& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath)
if (!$vsRoot) { throw 'Visual Studio x64 C++ build tools are required.' }
$vcVersion = (Get-Content -LiteralPath (Join-Path $vsRoot 'VC\Auxiliary\Build\Microsoft.VCToolsVersion.default.txt')).Trim()
$vc = Join-Path $vsRoot "VC\Tools\MSVC\$vcVersion"
$kits = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots').KitsRoot10
$bin = Join-Path $kits "bin\$SdkVersion\x64"
$cl = Join-Path $vc 'bin\Hostx64\x64\cl.exe'
$link = Join-Path $vc 'bin\Hostx64\x64\link.exe'
$dumpbin = Join-Path $vc 'bin\Hostx64\x64\dumpbin.exe'
$veiid = Join-Path $bin 'veiid.exe'
$um = Join-Path $kits "Lib\$SdkVersion\um\x64"
$crt = Join-Path $kits "Lib\$SdkVersion\ucrt\x64"
$ecrt = Join-Path $kits "Lib\$SdkVersion\ucrt_enclave\x64\ucrt.lib"
$eclib = Join-Path $vc 'lib\x64\enclave'
foreach ($required in @($cl, $link, $dumpbin, $veiid, $ecrt,
        (Join-Path $eclib 'libcmt.lib'), (Join-Path $um 'vertdll.lib'))) {
    if (!(Test-Path -LiteralPath $required)) { throw "Missing required tool/library: $required" }
}

# Use a Windows output directory; sources may remain in a WSL UNC checkout.
$OutDir = [IO.Path]::GetFullPath($OutDir)
if ($OutDir.StartsWith('\\')) { throw 'Choose a local Windows drive for OutDir.' }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
function Run-Native([string]$Exe, [string[]]$Arguments) {
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Native tool failed ($LASTEXITCODE): $Exe" }
}
$includes = @(
    "/I$(Join-Path $vc 'include')",
    "/I$(Join-Path $kits "Include\$SdkVersion\ucrt")",
    "/I$(Join-Path $kits "Include\$SdkVersion\shared")",
    "/I$(Join-Path $kits "Include\$SdkVersion\um")",
    "/I$PSScriptRoot"
)
$common = @('/nologo', '/c', '/O2', '/W4', '/WX', '/MT', '/std:c++17',
            '/guard:cf', '/sdl', '/utf-8', '/DUNICODE', '/D_UNICODE',
            '/DWINVER=0x0A00', '/D_WIN32_WINNT=0x0A00') + $includes
$enclaveObj = Join-Path $OutDir 'enclave_probe.obj'
$hostObj = Join-Path $OutDir 'probe_host.obj'
$cngObj = Join-Path $OutDir 'cng_primitives.obj'
$selfTestObj = Join-Path $OutDir 'crypto_self_test.obj'
$testHostObj = Join-Path $OutDir 'crypto_test_host.obj'
$materialObj = Join-Path $OutDir 'rlwe_material.obj'
$materialHostObj = Join-Path $OutDir 'material_test_host.obj'
$hpkeObj = Join-Path $OutDir 'hpke.obj'
$channelObj = Join-Path $OutDir 'material_channel.obj'
$installationObj = Join-Path $OutDir 'installation_verify.obj'
$channelEnclaveObj = Join-Path $OutDir 'channel_enclave.obj'
$channelTestObj = Join-Path $OutDir 'channel_test_host.obj'
$dll = Join-Path $OutDir 'hintless_vbs_probe.dll'
$exe = Join-Path $OutDir 'probe_host.exe'
$testExe = Join-Path $OutDir 'crypto_test_host.exe'
$materialExe = Join-Path $OutDir 'material_test_host.exe'
$channelTestExe = Join-Path $OutDir 'channel_test_host.exe'
Run-Native $cl ($common + @('/D_ENCLAVE', "/Fo$hpkeObj", (Join-Path $PSScriptRoot 'hpke.cc')))
Run-Native $cl ($common + @('/D_ENCLAVE', "/Fo$installationObj", (Join-Path $PSScriptRoot 'installation_verify.cc')))
Run-Native $cl ($common + @('/D_ENCLAVE', "/Fo$channelObj", (Join-Path $PSScriptRoot 'material_channel.cc')))
Run-Native $cl ($common + @('/D_ENCLAVE', "/Fo$channelEnclaveObj", (Join-Path $PSScriptRoot 'channel_enclave.cc')))
Run-Native $cl ($common + @('/D_ENCLAVE', "/Fo$materialObj", (Join-Path $PSScriptRoot 'rlwe_material.cc')))
Run-Native $cl ($common + @('/D_ENCLAVE', "/Fo$cngObj", (Join-Path $PSScriptRoot 'cng_primitives.cc')))
Run-Native $cl ($common + @('/D_ENCLAVE', "/Fo$selfTestObj", (Join-Path $PSScriptRoot 'crypto_self_test.cc')))
Run-Native $cl ($common + @('/D_ENCLAVE', "/Fo$enclaveObj", (Join-Path $PSScriptRoot 'enclave_probe.cc')))
Run-Native $link @('/nologo', '/DLL', '/MACHINE:X64', '/ENCLAVE',
    '/NODEFAULTLIB', '/INCREMENTAL:NO', '/INTEGRITYCHECK', '/GUARD:MIXED',
    '/DYNAMICBASE', '/NXCOMPAT', '/OPT:REF', '/OPT:ICF',
    "/DEF:$(Join-Path $PSScriptRoot 'enclave_probe.def')", "/OUT:$dll",
    $enclaveObj, $cngObj, $selfTestObj, $materialObj, $hpkeObj, $channelObj, $installationObj, $channelEnclaveObj, (Join-Path $eclib 'libcmt.lib'),
    (Join-Path $eclib 'libvcruntime.lib'), $ecrt,
    (Join-Path $um 'vertdll.lib'), (Join-Path $um 'bcrypt.lib'))
Run-Native $veiid @($dll)
Run-Native $cl ($common + @("/Fo$hostObj", (Join-Path $PSScriptRoot 'probe_host.cc')))
Run-Native $link @('/nologo', '/MACHINE:X64', '/SUBSYSTEM:CONSOLE',
    '/INCREMENTAL:NO', '/GUARD:CF', '/DYNAMICBASE', '/NXCOMPAT', "/OUT:$exe",
    "/LIBPATH:$(Join-Path $vc 'lib\x64')", "/LIBPATH:$crt", "/LIBPATH:$um",
    $hostObj, 'onecore.lib', 'bcrypt.lib')
Run-Native $cl ($common + @("/Fo$testHostObj", (Join-Path $PSScriptRoot 'crypto_test_host.cc')))
Run-Native $link @('/nologo', '/MACHINE:X64', '/SUBSYSTEM:CONSOLE',
    '/INCREMENTAL:NO', '/GUARD:CF', '/DYNAMICBASE', '/NXCOMPAT', "/OUT:$testExe",
    "/LIBPATH:$(Join-Path $vc 'lib\x64')", "/LIBPATH:$crt", "/LIBPATH:$um",
    $testHostObj, $cngObj, $selfTestObj, 'onecore.lib', 'bcrypt.lib')
$testOutput = & $testExe
if ($LASTEXITCODE -ne 0) { throw "Native crypto compatibility checks failed: $testOutput" }
$testResult = ($testOutput -join "`n") | ConvertFrom-Json
if (!$testResult.success -or $testResult.checks_passed -ne 59) { throw 'Incomplete native crypto compatibility checks.' }
$testResult | Add-Member -NotePropertyName timestamp_utc -NotePropertyValue ([DateTime]::UtcNow.ToString('o'))
$testResult | Add-Member -NotePropertyName test_binary_sha256 -NotePropertyValue ((Get-FileHash -LiteralPath $testExe -Algorithm SHA256).Hash)
$testResult | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutDir 'crypto-test-result.json') -Encoding UTF8
Run-Native $cl ($common + @("/Fo$materialHostObj", (Join-Path $PSScriptRoot 'material_test_host.cc')))
Run-Native $link @('/nologo', '/MACHINE:X64', '/SUBSYSTEM:CONSOLE',
    '/INCREMENTAL:NO', '/GUARD:CF', '/DYNAMICBASE', '/NXCOMPAT', "/OUT:$materialExe",
    "/LIBPATH:$(Join-Path $vc 'lib\x64')", "/LIBPATH:$crt", "/LIBPATH:$um",
    $materialHostObj, $materialObj, $cngObj, 'onecore.lib', 'bcrypt.lib')
Run-Native $cl ($common + @("/Fo$channelTestObj", (Join-Path $PSScriptRoot 'channel_test_host.cc')))
Run-Native $link @('/nologo', '/MACHINE:X64', '/SUBSYSTEM:CONSOLE',
    '/INCREMENTAL:NO', '/GUARD:CF', '/DYNAMICBASE', '/NXCOMPAT', "/OUT:$channelTestExe",
    "/LIBPATH:$(Join-Path $vc 'lib\x64')", "/LIBPATH:$crt", "/LIBPATH:$um",
    $channelTestObj, $channelObj, $hpkeObj, $materialObj, $cngObj, $installationObj, 'onecore.lib', 'bcrypt.lib')
$channelOutput = & $channelTestExe
if ($LASTEXITCODE -ne 0) { throw "Native channel checks failed: $channelOutput" }
$channelResult = ($channelOutput -join "`n") | ConvertFrom-Json
if (!$channelResult.success -or $channelResult.rfc_checks -ne 9 -or $channelResult.checks_passed -ne 34) {
    throw 'Incomplete channel checks.'
}
$channelResult | Add-Member -NotePropertyName timestamp_utc -NotePropertyValue ([DateTime]::UtcNow.ToString('o'))
$channelResult | Add-Member -NotePropertyName test_binary_sha256 -NotePropertyValue ((Get-FileHash -LiteralPath $channelTestExe).Hash)
$channelResult | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $OutDir 'channel-test-result.json') -Encoding UTF8

$imports = & $dumpbin /nologo /imports $dll
if ($LASTEXITCODE -ne 0) { throw 'Failed to inspect enclave imports.' }
$imports | Set-Content -LiteralPath (Join-Path $OutDir 'enclave-imports.txt') -Encoding UTF8
$importedDlls = @($imports | ForEach-Object {
    if ($_ -match '^\s+([a-zA-Z0-9_\-]+\.dll)\s*$') { $Matches[1].ToLowerInvariant() }
} | Sort-Object -Unique)
$allowedDlls = @('bcrypt.dll', 'ucrtbase_enclave.dll', 'vertdll.dll')
if ($importedDlls.Count -ne 3 -or @($importedDlls | Where-Object { $_ -notin $allowedDlls }).Count) {
    throw "Unexpected enclave platform imports: $importedDlls"
}
$headers = & $dumpbin /nologo /headers /loadconfig $dll
if ($LASTEXITCODE -ne 0) { throw 'Failed to inspect enclave configuration.' }
$headers | Set-Content -LiteralPath (Join-Path $OutDir 'enclave-headers.txt') -Encoding UTF8
if (!($headers -match '^\s+00000000 policy flags\s*$') -or
    !($headers -match '^\s+00000003 number of enclave import descriptors\s*$')) {
    throw 'Expected non-debug enclave and three VEIID-bound platform imports.'
}
$sources = @{}
foreach ($name in @('probe_abi.h','enclave_probe.cc','enclave_probe.def','probe_host.cc','build.ps1',
        'cng_primitives.h','cng_primitives.cc','crypto_self_test.h','crypto_self_test.cc','crypto_test_host.cc','test_vectors.h',
        'rlwe_material.h','rlwe_material.cc','material_test_abi.h','material_test_host.cc',
        'hpke.h','hpke.cc','hpke_test_vector.h','material_channel.h','material_channel.cc','channel_enclave.cc','channel_test_host.cc',
        'installation.h','installation_verify.cc','lifecycle_test_abi.h')) {
    $sources[$name] = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $PSScriptRoot $name)).Hash
}
[ordered]@{
    schema = 1
    timestamp_utc = [DateTime]::UtcNow.ToString('o')
    stage = 'compiled-vbs-encrypted-material-core-attestation-policy-incomplete'
    msvc = $vcVersion
    windows_sdk_folder = $SdkVersion
    veiid_file_version = (Get-Item -LiteralPath $veiid).VersionInfo.FileVersion
    debug_enclave = $false
    imported_platform_dlls = $importedDlls
    signing_applied_by_build = $false
    unsigned_enclave_sha256 = (Get-FileHash -LiteralPath $dll -Algorithm SHA256).Hash
    host_sha256 = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
    native_crypto_checks_passed = $testResult.checks_passed
    native_hpke_rfc_checks_passed = $channelResult.rfc_checks
    native_channel_checks_passed = $channelResult.checks_passed
    channel_test_host_sha256 = (Get-FileHash -LiteralPath $channelTestExe).Hash
    material_test_host_sha256 = (Get-FileHash -LiteralPath $materialExe -Algorithm SHA256).Hash
    source_sha256 = $sources
} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $OutDir 'build-manifest.json') -Encoding UTF8
Write-Output "Build complete: $OutDir"
