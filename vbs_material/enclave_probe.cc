#include <winenclave.h>
#include <bcrypt.h>
#include <stddef.h>

#include "probe_abi.h"
#include "crypto_self_test.h"
#include "hpke.h"
#include "material_test_abi.h"

// No IMAGE_ENCLAVE_POLICY_DEBUGGABLE, even for local test signing.
extern "C" const IMAGE_ENCLAVE_CONFIG __enclave_config = {
    sizeof(IMAGE_ENCLAVE_CONFIG), IMAGE_ENCLAVE_MINIMUM_CONFIG_SIZE,
    0, 0, 0, 0,
    {0x68, 0x70, 0x69, 0x72, 0x2d, 0x76, 0x62, 0x73,
     0x2d, 0x70, 0x72, 0x6f, 0x62, 0x65, 0x30, 0x31},
    {0x17, 0x45, 0x76, 0x92, 0x16, 0x38, 0x47, 0xa1,
     0xb8, 0x21, 0x94, 0x01, 0x65, 0x27, 0x35, 0x09},
    1, 1, kProbeEnclaveSize, 1, IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE};

extern "C" BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID) { return TRUE; }

namespace {
HRESULT RunProbe(const ProbeRequest& request, ProbeReply& reply) {
  ENCLAVE_INFORMATION information{};
  HRESULT hr = EnclaveGetEnclaveInformation(sizeof(information), &information);
  if (FAILED(hr)) return hr;
  reply.enclave_type = information.EnclaveType;
  reply.identity_flags = information.Identity.Flags;
  reply.signing_level = information.Identity.SigningLevel;
  reply.uses_attested_keys = EnclaveUsesAttestedKeys() ? 1 : 0;
  constexpr ULONG debug_mask = ENCLAVE_FLAG_FULL_DEBUG_ENABLED |
      ENCLAVE_FLAG_DYNAMIC_DEBUG_ENABLED | ENCLAVE_FLAG_DYNAMIC_DEBUG_ACTIVE;
  if (information.EnclaveType != ENCLAVE_TYPE_VBS ||
      (information.Identity.Flags & debug_mask) != 0) return E_ACCESSDENIED;

  hr = hintless_vbs::CryptoSelfTest(&reply.crypto_checks_passed);
  if (FAILED(hr)) return hr;
  ULONG hpke_checks = 0;
  hr = hintless_vbs::HpkeSelfTest(&hpke_checks);
  if (FAILED(hr) || hpke_checks != 9) return FAILED(hr) ? hr : E_FAIL;
  reply.crypto_checks_passed += hpke_checks;

  // This secret never crosses the enclave boundary. The commitment is public.
  BYTE secret_and_challenge[64]{};
  NTSTATUS status = BCryptGenRandom(nullptr, secret_and_challenge, 32,
                                    BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if (status < 0) {
    SecureZeroMemory(secret_and_challenge, sizeof(secret_and_challenge));
    return HRESULT_FROM_NT(status);
  }
  CopyMemory(secret_and_challenge + 32, request.challenge, 32);
  BCRYPT_ALG_HANDLE sha256 = nullptr;
  status = BCryptOpenAlgorithmProvider(&sha256, BCRYPT_SHA256_ALGORITHM,
                                       nullptr, 0);
  if (status >= 0) {
    status = BCryptHash(sha256, nullptr, 0, secret_and_challenge,
                        sizeof(secret_and_challenge), reply.random_commitment,
                        sizeof(reply.random_commitment));
  }
  SecureZeroMemory(secret_and_challenge, sizeof(secret_and_challenge));
  if (sha256) BCryptCloseAlgorithmProvider(sha256, 0);
  if (status < 0) return HRESULT_FROM_NT(status);

  // Bind a fresh host challenge and the public commitment into the report.
  // The diagnostic host is NOT a trusted remote attestation verifier.
  BYTE report_data[ENCLAVE_REPORT_DATA_LENGTH]{};
  CopyMemory(report_data, request.challenge, 32);
  CopyMemory(report_data + 32, reply.random_commitment, 32);
  UINT32 report_size = 0;
  hr = EnclaveGetAttestationReport(report_data, reply.report,
                                 sizeof(reply.report), &report_size);
  if (FAILED(hr)) {
    reply.report_size = 0;
    return hr;
  }
  reply.report_size = report_size;
  reply.local_report_verification = EnclaveVerifyAttestationReport(
      ENCLAVE_TYPE_VBS, reply.report, reply.report_size);
  return reply.local_report_verification;
}
}  // namespace

extern "C" void* CALLBACK HintlessVbsProbe(void* untrusted_exchange) {
  // Snapshot input exactly once. Never dereference a host pointer directly.
  ProbeRequest request{};
  HRESULT hr = EnclaveCopyIntoEnclave(&request, untrusted_exchange,
                                    sizeof(request));
  if (FAILED(hr)) return reinterpret_cast<void*>(static_cast<ULONG_PTR>(hr));
  if (request.version != kProbeVersion || request.size != sizeof(request))
    return reinterpret_cast<void*>(static_cast<ULONG_PTR>(E_INVALIDARG));

  auto* reply = static_cast<ProbeReply*>(
      HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ProbeReply)));
  if (!reply)
    return reinterpret_cast<void*>(static_cast<ULONG_PTR>(E_OUTOFMEMORY));
  reply->version = kProbeVersion;
  reply->size = sizeof(ProbeReply);
  reply->local_report_verification = E_PENDING;
  reply->operation_status = RunProbe(request, *reply);
  hr = EnclaveCopyOutOfEnclave(
      static_cast<BYTE*>(untrusted_exchange) + offsetof(ProbeExchange, reply),
      reply, sizeof(*reply));
  SecureZeroMemory(reply, sizeof(*reply));
  HeapFree(GetProcessHeap(), 0, reply);
  SecureZeroMemory(&request, sizeof(request));
  return reinterpret_cast<void*>(static_cast<ULONG_PTR>(hr));
}

// This entry point emits ONLY public-test materials with publicly known keys.
// The real private-channel provisioning endpoint is not implemented here.
extern "C" void* CALLBACK HintlessPublicMaterialTest(void* untrusted_exchange) {
  using namespace hintless_vbs;
  PublicMaterialTestRequest request{};
  HRESULT hr = EnclaveCopyIntoEnclave(&request, untrusted_exchange, sizeof(request));
  if (SUCCEEDED(hr) && (request.version != 1 || request.size != sizeof(request) || request.case_index > 255)) hr = E_INVALIDARG;
  ENCLAVE_INFORMATION information{};
  if (SUCCEEDED(hr)) hr = EnclaveGetEnclaveInformation(sizeof(information), &information);
  if (SUCCEEDED(hr) && (information.EnclaveType != ENCLAVE_TYPE_VBS ||
      (information.Identity.Flags & (ENCLAVE_FLAG_FULL_DEBUG_ENABLED |
       ENCLAVE_FLAG_DYNAMIC_DEBUG_ENABLED | ENCLAVE_FLAG_DYNAMIC_DEBUG_ACTIVE)))) hr = E_ACCESSDENIED;
  if (FAILED(hr)) return reinterpret_cast<void*>(static_cast<ULONG_PTR>(hr));
  auto* material = static_cast<RawMaterial*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(RawMaterial)));
  if (!material) return reinterpret_cast<void*>(static_cast<ULONG_PTR>(E_OUTOFMEMORY));
  BYTE master[32], id[32];
  PublicTestSecrets(request.case_index, master, id);
  hr = GenerateMaterial(request.config, id, master, material);
  SecureZeroMemory(master, sizeof(master));
  if (SUCCEEDED(hr)) hr = EnclaveCopyOutOfEnclave(
      static_cast<BYTE*>(untrusted_exchange) + offsetof(PublicMaterialTestExchange, material),
      material, sizeof(*material));
  SecureZeroMemory(material, sizeof(*material));
  HeapFree(GetProcessHeap(), 0, material);
  SecureZeroMemory(&request, sizeof(request));
  return reinterpret_cast<void*>(static_cast<ULONG_PTR>(hr));
}
