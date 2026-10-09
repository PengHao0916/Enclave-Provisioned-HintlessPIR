# Enclave-Provisioned HintlessPIR

Companion implementation for **Enclave-Provisioned HintlessPIR: Fresh Secrets with Compact Client Communication**.

This repository extends [HintlessPIR](https://github.com/google/hintless_pir) with one-time query material generated inside a Windows VBS enclave. For each logical query, the client supplies a fresh 256-bit seed. The enclave derives the LWE and RLWE secrets, generates the encrypted LWE secret and Galois keys, and delivers these objects to the PIR server. The client uploads the selection query and material identifiers. Database evaluation runs outside the enclave.

The implementation also uses HintlessPIR's public-component preprocessing: the client retains the public RLWE response coordinate and combines it with the online response during recovery.

## Query flow

1. The server preprocesses the database and provides the public reconstruction state.
2. The client sends a fresh seed through the enclave's HPKE channel. The enclave generates the corresponding query material.
3. The server installs the material and signs an installation receipt. The client records the accepted instance before issuing its query.
4. The server evaluates the query, and the client recovers the requested record. An exact retry returns the saved response; a new logical query uses fresh material.

The channel and installation protocol are described in [CHANNEL.md](vbs_material/CHANNEL.md). Query consumption and the client journal are described in [LIFECYCLE.md](vbs_material/LIFECYCLE.md).

## Code layout

| Directory | Contents |
| --- | --- |
| [`vbs_material/`](vbs_material/) | Windows enclave, HPKE channel, signed installation, persistent client journal, and Linux/Windows interoperability harness |
| [`local_material/`](local_material/) | Prepared client/server interfaces, software material generator, and protocol tests |
| [`hintless_simplepir/`](hintless_simplepir/) | HintlessPIR client, server, database evaluation, and serialization |
| [`linpir/`](linpir/) | Homomorphic hint evaluation |
| [`lwe/`](lwe/) | LWE encryption, sampling, and database operations |

## Build and run

The Linux components use C++17, Bazel 7.2.1, and Python 3. The manuscript experiments used Ubuntu 22.04.1 under WSL2, GCC 11.4.0, and a Windows 11 host with an Intel Core i7-14650HX and 32 GiB of memory.

```bash
git clone https://github.com/PengHao0916/Enclave-Provisioned-HintlessPIR.git
cd Enclave-Provisioned-HintlessPIR

bazel test -c opt --jobs=4 \
  //local_material:protocol_test \
  //vbs_material:client_journal_test
```

The software backend provides a short functional run without a Windows enclave:

```bash
bazel run -c opt //local_material:local_worker -- demo 5 functional
bazel run -c opt //local_material:local_worker -- demo 3 8mb
```

These commands run the software generator. The Windows VBS path uses a separate host executable and a signed enclave DLL.

### Windows VBS backend

Build the Windows binaries from PowerShell with the Visual Studio x64 C++ tools and Windows SDK 10.0.26100.0 installed:

```powershell
.\vbs_material\build.ps1 -OutDir C:\Temp\hintlesspir-vbs
```

Complete the enclave signing and platform setup described in [vbs_material/README.md](vbs_material/README.md), then run the private-seed path from WSL:

```bash
mkdir -p /mnt/c/Temp/hintlesspir-results
bazel run -c opt --jobs=4 //vbs_material:material_interop_test -- \
  enclave-private-lifecycle 8mb \
  /mnt/c/Temp/hintlesspir-vbs/channel_test_host.exe \
  /mnt/c/Temp/hintlesspir-results \
  'C:\Temp\hintlesspir-vbs\hintless_vbs_probe.dll'
```

The harness connects the Linux evaluator to the Windows enclave. Its JSON output records recovery, RLWE noise checks, exact retries, reuse rejection, and phase timings. Attestation in this harness uses local report binding.

## Manuscript results

The following measurements use fresh query material and one evaluator worker. Upload includes client provisioning messages; download is the online response. Server time covers query handling after material installation.

| Database | Record size | Client upload | Online download | Mean server time |
| --- | --- | --- | --- | --- |
| 8 MiB | 8 B | 5.74 KiB | 0.742 MiB | 271.73 ms |
| 512 MiB | 32 B | 20.55 KiB | 11.872 MiB | 1.607 s |
| 1 GiB | 16 B | 40.29 KiB | 11.872 MiB | 1.614 s |
| 1 GiB | 1 B | 158.78 KiB | 2.968 MiB | 627.70 ms |

At 8 MiB, client upload falls from 365 KiB for the full-upload HintlessPIR baseline to 5.74 KiB. Public-component preprocessing halves the RLWE response portion in exchange for client reconstruction state. Record width and database layout determine the size of that state and the remaining online response.

## Source and license

The PIR evaluator is based on [Google HintlessPIR](https://github.com/google/hintless_pir) and [shell-encryption](https://github.com/google/shell-encryption). The original construction is described in [Hintless single-server private information retrieval](https://eprint.iacr.org/2023/1733). Earlier session-caching documentation is retained in [docs/legacy_readme.md](docs/legacy_readme.md).

The code is distributed under the [Apache License 2.0](LICENSE).
