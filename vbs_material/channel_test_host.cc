// PUBLIC FIXTURE DIAGNOSTIC ONLY. The fixture verifier below is intentionally
// not a real attestation verifier and is NOT linked into the enclave DLL.
#include "material_channel.h"
#include "material_test_abi.h"
#include "lifecycle_test_abi.h"
#include <fcntl.h>
#include <io.h>
#include <stdio.h>
#include <string.h>
#include <chrono>
#include <memory>
#include <vector>
#include <ntenclv.h>

namespace {
using namespace hintless_vbs;
std::vector<const char*> passed;
bool Check(bool result, const char* name) {
  if (!result) fprintf(stderr, "Channel check failed: %s\n", name);
  else passed.push_back(name);
  return result;
}
bool IsZero(const void* pointer, size_t size) {
  const BYTE* p = static_cast<const BYTE*>(pointer);
  BYTE sum = 0;
  for (size_t i = 0; i < size; ++i) sum |= p[i];
  return sum == 0;
}
class PublicFixtureVerifier final : public AttestationVerifier {
 public:
  HRESULT Verify(const BYTE* report, ULONG size, const BYTE data[64]) const override {
    return size == 64 && ConstantTimeEqual(report, data, 64) ? S_OK : E_ACCESSDENIED;
  }
};
class FalseSuccessVerifier final : public AttestationVerifier {
 public:
  HRESULT Verify(const BYTE*, ULONG, const BYTE[64]) const override { return S_FALSE; }
};
// Checks ONLY framing and bound data. There is NO platform-signature trust here.
// Used solely below with PUBLIC fixed seeds, never for a private client session.
class PublicReportBindingOnlyVerifier final : public AttestationVerifier {
 public:
  HRESULT Verify(const BYTE* bytes, ULONG size, const BYTE expected[64]) const override {
    if (size < sizeof(VBS_ENCLAVE_REPORT_PKG_HEADER) + sizeof(VBS_ENCLAVE_REPORT) ||
        size > kMaxReportBytes) return E_INVALIDARG;
    VBS_ENCLAVE_REPORT_PKG_HEADER package{};
    CopyMemory(&package, bytes, sizeof(package));
    if (package.Version != VBS_ENCLAVE_REPORT_PKG_HEADER_VERSION_CURRENT ||
        package.PackageSize != size || package.SignedStatementSize < sizeof(VBS_ENCLAVE_REPORT) ||
        package.SignedStatementSize > size - sizeof(package) ||
        package.SignatureSize != size - sizeof(package) - package.SignedStatementSize) return E_INVALIDARG;
    VBS_ENCLAVE_REPORT report{};
    CopyMemory(&report, bytes + sizeof(package), sizeof(report));
    if (report.ReportVersion != VBS_ENCLAVE_REPORT_VERSION_CURRENT ||
        report.ReportSize != package.SignedStatementSize ||
        report.EnclaveIdentity.EnclaveType != ENCLAVE_TYPE_VBS ||
        (report.EnclaveIdentity.Flags & (ENCLAVE_FLAG_FULL_DEBUG_ENABLED |
          ENCLAVE_FLAG_DYNAMIC_DEBUG_ENABLED | ENCLAVE_FLAG_DYNAMIC_DEBUG_ACTIVE)) ||
        !ConstantTimeEqual(report.EnclaveData, expected, 64)) return E_ACCESSDENIED;
    return S_OK;
  }
};
struct PublicEnclaveRun {
  void* address = nullptr;
  bool initialized = false;
  const char* stage = "CreateEnclave";
  ~PublicEnclaveRun() {
    if (initialized) TerminateEnclave(address, TRUE);
    if (address) DeleteEnclave(address);
  }
  HRESULT Call(const char* name, void* exchange) {
    stage = name;
    auto routine = reinterpret_cast<LPENCLAVE_ROUTINE>(GetProcAddress(static_cast<HMODULE>(address), name));
    if (!routine) return HRESULT_FROM_WIN32(GetLastError());
    void* result = nullptr;
    if (!CallEnclave(routine, exchange, TRUE, &result)) return HRESULT_FROM_WIN32(GetLastError());
    return static_cast<HRESULT>(reinterpret_cast<ULONG_PTR>(result));
  }
  HRESULT Load(const wchar_t* dll) {
    ENCLAVE_CREATE_INFO_VBS create{};
    address = CreateEnclave(GetCurrentProcess(), nullptr, kProbeEnclaveSize,
                            0, ENCLAVE_TYPE_VBS, &create, sizeof(create), nullptr);
    if (!address) return HRESULT_FROM_WIN32(GetLastError());
    stage = "LoadEnclaveImageW";
    DWORD previous = 0;
    SetThreadErrorMode(GetThreadErrorMode() | SEM_FAILCRITICALERRORS, &previous);
    BOOL loaded = LoadEnclaveImageW(address, dll);
    DWORD error = loaded ? 0 : GetLastError();
    SetThreadErrorMode(previous, nullptr);
    if (!loaded) return HRESULT_FROM_WIN32(error);
    stage = "InitializeEnclave";
    ENCLAVE_INIT_INFO_VBS init{sizeof(init), 1};
    if (!InitializeEnclave(GetCurrentProcess(), address, &init, sizeof(init), nullptr))
      return HRESULT_FROM_WIN32(GetLastError());
    initialized = true;
    return S_OK;
  }
};
HRESULT FixtureOffer(MaterialChannelReceiver& receiver, const ChannelHello& hello, ChannelOffer* offer) {
  HRESULT hr = receiver.Begin(hello, offer);
  if (SUCCEEDED(hr)) hr = ChannelReportData(hello, *offer, offer->report);
  if (SUCCEEDED(hr)) offer->report_size = 64;
  return hr;
}
ChannelHello Hello(const PublicMaterialTestRequest& input, BYTE master[32]) {
  ChannelHello hello{};
  hello.version = 1; hello.size = sizeof(hello); hello.config = input.config;
  PublicTestSecrets(input.case_index, master, hello.material_id);
  for (ULONG i = 0; i < 32; ++i) hello.challenge[i] = static_cast<BYTE>(i + 11 + input.case_index);
  return hello;
}
ChannelHello Hello(const PrivateResearchMaterialRequest& input) {
  ChannelHello hello{};
  hello.version = 1; hello.size = sizeof(hello); hello.config = input.config;
  CopyMemory(hello.material_id, input.material_id, 32);
  CopyMemory(hello.challenge, input.challenge, 32);
  return hello;
}
uint64_t ElapsedNs(std::chrono::steady_clock::time_point start) {
  return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
      std::chrono::steady_clock::now() - start).count());
}
bool GenerateFixture(const PublicMaterialTestRequest& input, RawMaterial* material) {
  BYTE master[32];
  auto hello = Hello(input, master);
  MaterialChannelReceiver receiver;
  MaterialChannelClient client;
  PublicFixtureVerifier verifier;
  auto offer = std::make_unique<ChannelOffer>();
  SealedPreparation request{};
  GenerationReceipt receipt{};
  return SUCCEEDED(FixtureOffer(receiver, hello, offer.get())) &&
      SUCCEEDED(client.Seal(hello, *offer, verifier, master, &request)) &&
      SUCCEEDED(receiver.Generate(request, material, &receipt)) &&
      SUCCEEDED(client.AcceptReceipt(receipt));
}
HRESULT GenerateEnclaveFixture(const PublicMaterialTestRequest& input, const wchar_t* dll,
                                RawMaterial* material, const char** stage) {
  PublicEnclaveRun enclave;
  HRESULT hr = enclave.Load(dll);
  BYTE master[32];
  auto begin = std::make_unique<ChannelBeginExchange>();
  begin->request = Hello(input, master);
  auto generate = std::make_unique<ChannelGenerateExchange>();
  MaterialChannelClient client;
  PublicReportBindingOnlyVerifier binding_only;
  if (SUCCEEDED(hr)) hr = enclave.Call("HintlessChannelBegin", begin.get());
  if (SUCCEEDED(hr)) {
    enclave.stage = "PublicFixtureSealBindingOnly";
    hr = client.Seal(begin->request, begin->reply, binding_only, master, &generate->request);
  }
  if (SUCCEEDED(hr)) hr = enclave.Call("HintlessChannelGenerate", generate.get());
  if (SUCCEEDED(hr)) {
    enclave.stage = "AcceptGenerationReceipt";
    hr = client.AcceptReceipt(generate->receipt);
  }
  if (SUCCEEDED(hr)) {
    CopyMemory(material, &generate->material, sizeof(*material));
    auto original_receipt = generate->receipt;
    hr = enclave.Call("HintlessChannelGenerate", generate.get());
    if (SUCCEEDED(hr) && (memcmp(material, &generate->material, sizeof(*material)) ||
        memcmp(&original_receipt, &generate->receipt, sizeof(original_receipt)))) hr = E_FAIL;
  }
  if (SUCCEEDED(hr)) {
    generate->request.encrypted_seed[0] ^= 1;
    if (SUCCEEDED(enclave.Call("HintlessChannelGenerate", generate.get()))) hr = E_FAIL;
  }
  if (SUCCEEDED(hr)) hr = enclave.Call("HintlessChannelClose", nullptr);
  *stage = SUCCEEDED(hr) ? "complete" : enclave.stage;
  return hr;
}
// A live public-fixture client waits for the REAL Linux PIR server's signed
// installation receipt. Only then can it authorize one query. Binary pipe mode
// deliberately accepts no secret seed: Hello derives publicly known test data.
int Lifecycle(const wchar_t* dll) {
  if (_setmode(_fileno(stdin), _O_BINARY) == -1 ||
      _setmode(_fileno(stdout), _O_BINARY) == -1) return 2;
  PublicLifecycleInput input{};
  if (fread(&input, 1, sizeof(input), stdin) != sizeof(input) ||
      input.request.version != 1 || input.request.size != sizeof(input.request) ||
      input.request.case_index > 255 || !IsZero(input.reserved, sizeof(input.reserved))) return 3;
  BYTE master[32];
  auto begin = std::make_unique<ChannelBeginExchange>();
  begin->request = Hello(input.request, master);
  auto generate = std::make_unique<ChannelGenerateExchange>();
  PublicEnclaveRun enclave;
  MaterialChannelReceiver receiver;
  MaterialChannelClient client;
  PublicFixtureVerifier fixture;
  PublicReportBindingOnlyVerifier binding_only;
  HRESULT hr = dll ? enclave.Load(dll) : S_OK;
  if (SUCCEEDED(hr)) hr = dll ? enclave.Call("HintlessChannelBegin", begin.get()) :
      FixtureOffer(receiver, begin->request, &begin->reply);
  if (SUCCEEDED(hr)) hr = client.Seal(begin->request, begin->reply,
      dll ? static_cast<const AttestationVerifier&>(binding_only) : fixture, master, &generate->request);
  SecureZeroMemory(master, sizeof(master));
  if (SUCCEEDED(hr)) hr = dll ? enclave.Call("HintlessChannelGenerate", generate.get()) :
      receiver.Generate(generate->request, &generate->material, &generate->receipt);
  if (SUCCEEDED(hr)) hr = client.AcceptReceipt(generate->receipt);
  InstallationBinding binding{};
  if (SUCCEEDED(hr) && (client.ReadyForQuery() || SUCCEEDED(client.ConsumeForQuery()))) hr = E_FAIL;
  if (SUCCEEDED(hr)) hr = client.BeginInstallation(input.server_epoch, &binding);
  if (fwrite(&hr, 1, sizeof(hr), stdout) != sizeof(hr)) return 4;
  if (FAILED(hr)) {
    fflush(stdout);
    fprintf(stderr, "Lifecycle preparation failed at %s: 0x%08lX\n", enclave.stage, static_cast<ULONG>(hr));
    return 5;
  }
  if (fwrite(&generate->material, 1, sizeof(generate->material), stdout) != sizeof(generate->material) ||
      fwrite(&binding, 1, sizeof(binding), stdout) != sizeof(binding) || fflush(stdout)) return 6;
  InstallationAck ack{};
  if (fread(&ack, 1, sizeof(ack), stdin) != sizeof(ack)) return 7;
  hr = client.AcceptInstallation(ack, input.pinned_server_key);
  if (SUCCEEDED(hr) && !client.ReadyForQuery()) hr = E_FAIL;
  if (SUCCEEDED(hr)) hr = client.ConsumeForQuery();
  if (SUCCEEDED(hr) && (client.ReadyForQuery() || SUCCEEDED(client.ConsumeForQuery()) ||
      SUCCEEDED(client.AcceptInstallation(ack, input.pinned_server_key)))) hr = E_FAIL;
  if (dll && SUCCEEDED(hr)) hr = enclave.Call("HintlessChannelClose", nullptr);
  if (fwrite(&hr, 1, sizeof(hr), stdout) != sizeof(hr) || fflush(stdout)) return 8;
  // Authentication rejection is returned in-band for negative test cases.
  return 0;
}

// Local research client. The parent supplies fresh random client data over an
// inherited pipe. Only the sealed request crosses the enclave boundary; the
// seed is never emitted in the public material stream.
int PrivateResearchLifecycle(const wchar_t* dll) {
  if (_setmode(_fileno(stdin), _O_BINARY) == -1 ||
      _setmode(_fileno(stdout), _O_BINARY) == -1) return 2;
  PrivateResearchLifecycleInput input{};
  if (fread(&input, 1, sizeof(input), stdin) != sizeof(input) ||
      input.request.version != 1 || input.request.size != sizeof(input.request) ||
      !IsZero(input.reserved, sizeof(input.reserved))) return 3;
  PrivateResearchLifecycleMetrics metrics{};
  metrics.version = 1; metrics.size = sizeof(metrics);
  const auto total_start = std::chrono::steady_clock::now();
  BYTE master[32];
  CopyMemory(master, input.request.master_seed, sizeof(master));
  SecureZeroMemory(input.request.master_seed, sizeof(input.request.master_seed));
  const ChannelHello hello = Hello(input.request);
  auto begin = std::make_unique<ChannelBeginExchange>();
  begin->request = hello;
  auto generate = std::make_unique<ChannelGenerateExchange>();
  PublicEnclaveRun enclave;
  MaterialChannelReceiver receiver;
  MaterialChannelClient client;
  PublicFixtureVerifier fixture;
  PublicReportBindingOnlyVerifier binding_only;

  auto stage_start = std::chrono::steady_clock::now();
  HRESULT hr = dll ? enclave.Load(dll) : S_OK;
  metrics.enclave_load_ns = dll ? ElapsedNs(stage_start) : 0;
  stage_start = std::chrono::steady_clock::now();
  if (SUCCEEDED(hr)) hr = dll ? enclave.Call("HintlessChannelBegin", begin.get()) :
      FixtureOffer(receiver, begin->request, &begin->reply);
  metrics.channel_begin_ns = ElapsedNs(stage_start);
  stage_start = std::chrono::steady_clock::now();
  if (SUCCEEDED(hr)) hr = client.Seal(begin->request, begin->reply,
      dll ? static_cast<const AttestationVerifier&>(binding_only) : fixture,
      master, &generate->request);
  metrics.client_seal_ns = ElapsedNs(stage_start);
  SecureZeroMemory(master, sizeof(master));
  stage_start = std::chrono::steady_clock::now();
  if (SUCCEEDED(hr)) hr = dll ? enclave.Call("HintlessChannelGenerate", generate.get()) :
      receiver.Generate(generate->request, &generate->material, &generate->receipt);
  metrics.enclave_generate_ns = ElapsedNs(stage_start);
  stage_start = std::chrono::steady_clock::now();
  if (SUCCEEDED(hr)) hr = client.AcceptReceipt(generate->receipt);
  metrics.receipt_accept_ns = ElapsedNs(stage_start);
  InstallationBinding binding{};
  if (SUCCEEDED(hr)) hr = client.BeginInstallation(input.server_epoch, &binding);
  if (fwrite(&hr, 1, sizeof(hr), stdout) != sizeof(hr)) return 4;
  if (FAILED(hr)) {
    fflush(stdout);
    fprintf(stderr, "Private research preparation failed at %s: 0x%08lX\n",
            enclave.stage, static_cast<ULONG>(hr));
    SecureZeroMemory(&input, sizeof(input));
    return 5;
  }
  stage_start = std::chrono::steady_clock::now();
  if (fwrite(&generate->material, 1, sizeof(generate->material), stdout) != sizeof(generate->material) ||
      fwrite(&binding, 1, sizeof(binding), stdout) != sizeof(binding) || fflush(stdout)) return 6;
  InstallationAck ack{};
  if (fread(&ack, 1, sizeof(ack), stdin) != sizeof(ack)) return 7;
  hr = client.AcceptInstallation(ack, input.pinned_server_key);
  metrics.installation_roundtrip_ns = ElapsedNs(stage_start);
  if (SUCCEEDED(hr) && !client.ReadyForQuery()) hr = E_FAIL;
  if (SUCCEEDED(hr)) hr = client.ConsumeForQuery();
  if (SUCCEEDED(hr) && (client.ReadyForQuery() || SUCCEEDED(client.ConsumeForQuery()) ||
      SUCCEEDED(client.AcceptInstallation(ack, input.pinned_server_key)))) hr = E_FAIL;
  if (dll && SUCCEEDED(hr)) hr = enclave.Call("HintlessChannelClose", nullptr);
  metrics.total_ns = ElapsedNs(total_start);
  SecureZeroMemory(&input, sizeof(input));
  if (fwrite(&hr, 1, sizeof(hr), stdout) != sizeof(hr) ||
      fwrite(&metrics, 1, sizeof(metrics), stdout) != sizeof(metrics) || fflush(stdout)) return 8;
  return 0;
}

bool Tests(ULONG* rfc_checks) {
  if (!Check(SUCCEEDED(HpkeSelfTest(rfc_checks)) && *rfc_checks == 9, "rfc9180_A3_1")) return false;
  PublicMaterialTestRequest fixture{};
  fixture.version = 1; fixture.size = sizeof(fixture);
  fixture.config.profile = MaterialProfile::kFunctional;
  for (ULONG i = 0; i < 32; ++i) fixture.config.configuration_id[i] = static_cast<BYTE>(i + 101);
  BYTE master[32];
  auto hello = Hello(fixture, master);
  PublicFixtureVerifier verifier;
  auto material = std::make_unique<RawMaterial>();
  auto retry = std::make_unique<RawMaterial>();
  auto offer = std::make_unique<ChannelOffer>();
  GenerationReceipt receipt{}, retry_receipt{};
  SealedPreparation request{};
  {
    MaterialChannelReceiver receiver;
    if (!Check(SUCCEEDED(FixtureOffer(receiver, hello, offer.get())), "begin")) return false;
    UnavailableAttestationVerifier missing;
    MaterialChannelClient blocked;
    if (!Check(blocked.Seal(hello, *offer, missing, master, &request) == E_NOTIMPL &&
               IsZero(&request, sizeof(request)), "no_verifier_no_seed_packet")) return false;
    FalseSuccessVerifier false_success;
    MaterialChannelClient bad_status;
    if (!Check(FAILED(bad_status.Seal(hello, *offer, false_success, master, &request)) &&
               IsZero(&request, sizeof(request)), "s_false_is_not_approval")) return false;
    MaterialChannelClient client;
    if (!Check(SUCCEEDED(client.Seal(hello, *offer, verifier, master, &request)), "seal")) return false;
    if (!Check(SUCCEEDED(receiver.Generate(request, material.get(), &receipt)), "generate")) return false;
    BYTE digest[32];
    if (!Check(SUCCEEDED(Sha256(reinterpret_cast<const BYTE*>(material.get()), sizeof(*material), digest)) &&
               ConstantTimeEqual(digest, receipt.material_digest, 32), "receipt_matches_material")) return false;
    if (!Check(SUCCEEDED(client.AcceptReceipt(receipt)), "accept_receipt")) return false;
    if (!Check(FAILED(client.AcceptReceipt(receipt)), "receipt_cannot_complete_twice")) return false;
    if (!Check(SUCCEEDED(receiver.Generate(request, retry.get(), &retry_receipt)) &&
               memcmp(material.get(), retry.get(), sizeof(*material)) == 0 &&
               memcmp(&receipt, &retry_receipt, sizeof(receipt)) == 0, "exact_retry_public_cache")) return false;
    auto changed = request; changed.encrypted_seed[0] ^= 1;
    if (!Check(FAILED(receiver.Generate(changed, retry.get(), &retry_receipt)) &&
               IsZero(retry.get(), sizeof(*retry)), "different_request_after_consumption")) return false;
    if (!Check(FAILED(receiver.Begin(hello, offer.get())), "no_second_begin_same_instance")) return false;
    if (!Check(FAILED(client.Seal(hello, *offer, verifier, master, &changed)), "client_one_preparation")) return false;
  }
  {
    MaterialChannelReceiver restarted;
    if (!Check(SUCCEEDED(FixtureOffer(restarted, hello, offer.get())) &&
               !ConstantTimeEqual(offer->transcript, request.transcript, 32), "new_instance_fresh_key")) return false;
    if (!Check(FAILED(restarted.Generate(request, retry.get(), &retry_receipt)), "old_packet_after_restart")) return false;
  }
  // Each unauthenticated/invalid packet consumes the fresh receiver attempt.
  const char* corrupt_names[] = {"ciphertext_tamper", "tag_tamper", "invalid_curve_point", "transcript_tamper",
                                "request_version", "request_size", "reserved_bytes"};
  for (ULONG c = 0; c < 7; ++c) {
    MaterialChannelReceiver receiver;
    MaterialChannelClient client;
    if (FAILED(FixtureOffer(receiver, hello, offer.get())) ||
        FAILED(client.Seal(hello, *offer, verifier, master, &request))) return false;
    auto changed = request;
    switch (c) {
      case 0: changed.encrypted_seed[0] ^= 1; break;
      case 1: changed.encrypted_seed[47] ^= 1; break;
      case 2: ZeroMemory(changed.encapsulation, 65); changed.encapsulation[0] = 4; break;
      case 3: changed.transcript[0] ^= 1; break;
      case 4: changed.version = 2; break;
      case 5: changed.size--; break;
      case 6: changed.reserved[0] = 1; break;
    }
    if (!Check(FAILED(receiver.Generate(changed, material.get(), &receipt)) &&
               IsZero(material.get(), sizeof(*material)) && IsZero(&receipt, sizeof(receipt)) &&
               FAILED(receiver.Generate(request, material.get(), &receipt)), corrupt_names[c])) return false;
  }
  const char* offer_names[] = {"offer_key_substitution", "configuration_substitution", "material_id_substitution",
                              "challenge_substitution", "missing_report", "oversized_report", "corrupt_report", "offer_version"};
  for (ULONG c = 0; c < 8; ++c) {
    MaterialChannelReceiver receiver;
    MaterialChannelClient client;
    if (FAILED(FixtureOffer(receiver, hello, offer.get()))) return false;
    auto expected = hello;
    switch (c) {
      case 0: { P256Key fake; if (FAILED(fake.Generate(offer->recipient_key))) return false;
                if (FAILED(ChannelTranscript(hello, offer->recipient_key, offer->transcript))) return false; break; }
      case 1: expected.config.ciphertext_pad_seeds[0][0] ^= 1; break;
      case 2: expected.material_id[0] ^= 1; break;
      case 3: expected.challenge[0] ^= 1; break;
      case 4: offer->report_size = 0; break;
      case 5: offer->report_size = kMaxReportBytes + 1; break;
      case 6: offer->report[0] ^= 1; break;
      case 7: offer->version++; break;
    }
    if (!Check(FAILED(client.Seal(expected, *offer, verifier, master, &request)) &&
               IsZero(&request, sizeof(request)), offer_names[c])) return false;
  }
  const char* receipt_names[] = {"receipt_digest_tamper", "receipt_mac_tamper", "receipt_request_substitution", "receipt_session_substitution"};
  for (ULONG c = 0; c < 4; ++c) {
    MaterialChannelReceiver receiver;
    MaterialChannelClient client;
    if (FAILED(FixtureOffer(receiver, hello, offer.get())) ||
        FAILED(client.Seal(hello, *offer, verifier, master, &request)) ||
        FAILED(receiver.Generate(request, material.get(), &receipt))) return false;
    auto changed = receipt;
    if (c == 0) changed.material_digest[0] ^= 1;
    else if (c == 1) changed.mac[0] ^= 1;
    else if (c == 2) changed.request_digest[0] ^= 1;
    else changed.transcript[0] ^= 1;
    if (!Check(FAILED(client.AcceptReceipt(changed)) && FAILED(client.AcceptReceipt(receipt)), receipt_names[c])) return false;
  }
  return true;
}
}  // namespace

int wmain(int argc, wchar_t** argv) {
  if (argc == 2 && wcscmp(argv[1], L"--native-lifecycle") == 0) return Lifecycle(nullptr);
  if (argc == 3 && wcscmp(argv[1], L"--enclave-lifecycle") == 0) return Lifecycle(argv[2]);
  if (argc == 2 && wcscmp(argv[1], L"--private-native-lifecycle") == 0)
    return PrivateResearchLifecycle(nullptr);
  if (argc == 3 && wcscmp(argv[1], L"--private-enclave-lifecycle") == 0)
    return PrivateResearchLifecycle(argv[2]);
  if (argc == 1) {
    ULONG rfc_checks = 0;
    const bool success = Tests(&rfc_checks);
    printf("{\"backend\":\"native-encrypted-channel-NOT-TEE\",\"public_test_secrets_only\":true,"
           "\"real_attestation_verified\":false,\"success\":%s,\"rfc_checks\":%lu,\"checks_passed\":%zu,\"checks\":[",
           success ? "true" : "false", rfc_checks, passed.size());
    for (size_t i = 0; i < passed.size(); ++i) printf("%s\"%s\"", i ? "," : "", passed[i]);
    puts("]}");
    return success ? 0 : 1;
  }
  // Existing Linux interop harness supplies public configuration and known test
  // case index. There is deliberately no arbitrary-secret or verifier-bypass CLI.
  const bool native = argc == 4 && wcscmp(argv[1], L"--native") == 0;
  const bool enclave = argc == 5 && wcscmp(argv[1], L"--enclave") == 0;
  if (!native && !enclave) return 2;
  PublicMaterialTestRequest input{};
  FILE* file = nullptr;
  if (_wfopen_s(&file, argv[argc - 2], L"rb") || !file) return 3;
  bool valid = fread(&input, 1, sizeof(input), file) == sizeof(input) && fgetc(file) == EOF;
  fclose(file);
  if (!valid || input.version != 1 || input.size != sizeof(input) || input.case_index > 255) return 4;
  auto material = std::make_unique<RawMaterial>();
  const char* stage = "NativePublicFixture";
  HRESULT hr = native ? (GenerateFixture(input, material.get()) ? S_OK : E_FAIL) :
      GenerateEnclaveFixture(input, argv[2], material.get(), &stage);
  if (FAILED(hr)) {
    printf("{\"backend\":\"%s\",\"public_test_secrets_only\":true,\"real_attestation_verified\":false,"
           "\"success\":false,\"stage\":\"%s\",\"hresult\":\"0x%08lX\"}\n",
           native ? "native-encrypted-material-NOT-TEE" : "vbs-encrypted-material-public-test", stage, static_cast<ULONG>(hr));
    return 5;
  }
  if (_wfopen_s(&file, argv[argc - 1], L"wb") || !file) return 6;
  bool written = fwrite(material.get(), 1, sizeof(*material), file) == sizeof(*material);
  if (fclose(file)) written = false;
  printf("{\"backend\":\"%s\",\"public_test_secrets_only\":true,"
         "\"real_attestation_verified\":false,\"success\":%s}\n",
         native ? "native-encrypted-material-NOT-TEE" : "vbs-encrypted-material-public-test", written ? "true" : "false");
  return written ? 0 : 7;
}
