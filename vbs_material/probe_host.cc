#include <windows.h>
#include <bcrypt.h>
#include <ntenclv.h>
#include <stdio.h>
#include <string.h>

#include "probe_abi.h"

namespace {
struct Result {
  bool supported = false;
  bool created = false;
  bool loaded = false;
  bool initialized = false;
  bool called = false;
  bool checked = false;
  bool malformed_rejected = false;
  bool null_rejected = false;
  bool report_saved = false;
  bool deleted = false;
  const char* stage = "support";
  DWORD error = 0;
  HRESULT operation_status = E_PENDING;
  HRESULT local_verification = E_PENDING;
  ULONG identity_flags = 0;
  ULONG report_bytes = 0;
  ULONG attested_keys = 0;
  ULONG crypto_checks = 0;
  DWORD cleanup_error = 0;
};

const char* Bool(bool value) { return value ? "true" : "false"; }
void Emit(const Result& r) {
  printf("{\n  \"backend\": \"windows-vbs-enclave-probe\",\n"
         "  \"vbs_supported\": %s,\n  \"enclave_created\": %s,\n"
         "  \"image_loaded\": %s,\n  \"enclave_initialized\": %s,\n"
         "  \"enclave_called\": %s,\n  \"probe_validated\": %s,\n"
         "  \"malformed_abi_rejected\": %s,\n  \"null_input_rejected\": %s,\n"
         "  \"debug_requested\": false,\n  \"identity_flags\": %lu,\n"
         "  \"uses_attested_keys\": %lu,\n  \"report_bytes\": %lu,\n"
         "  \"report_saved\": %s,\n  \"enclave_deleted\": %s,\n"
         "  \"stage\": \"%s\",\n  \"win32_error\": %lu,\n"
         "  \"operation_hresult\": \"0x%08lX\",\n"
         "  \"local_report_verification_hresult\": \"0x%08lX\",\n"
         "  \"cleanup_error\": %lu,\n"
         "  \"enclave_crypto_checks_passed\": %lu,\n"
         "  \"client_attestation_verification\": null,\n"
         "  \"confidential_seed_channel_implemented\": false,\n"
         "  \"hpke_seed_channel_core_compiled\": true,\n"
         "  \"public_material_core_compiled\": true,\n"
         "  \"private_material_backend_implemented\": false\n}\n",
         Bool(r.supported), Bool(r.created), Bool(r.loaded), Bool(r.initialized),
         Bool(r.called), Bool(r.checked), Bool(r.malformed_rejected),
         Bool(r.null_rejected), r.identity_flags, r.attested_keys, r.report_bytes,
         Bool(r.report_saved), Bool(r.deleted), r.stage, r.error,
         static_cast<ULONG>(r.operation_status),
         static_cast<ULONG>(r.local_verification), r.cleanup_error, r.crypto_checks);
}

bool CheckReport(const ProbeExchange& exchange) {
  const auto& reply = exchange.reply;
  constexpr ULONG debug_mask = ENCLAVE_FLAG_FULL_DEBUG_ENABLED |
      ENCLAVE_FLAG_DYNAMIC_DEBUG_ENABLED | ENCLAVE_FLAG_DYNAMIC_DEBUG_ACTIVE;
  if (reply.version != kProbeVersion || reply.size != sizeof(reply) ||
      FAILED(reply.operation_status) || FAILED(reply.local_report_verification) ||
      reply.enclave_type != ENCLAVE_TYPE_VBS ||
      (reply.identity_flags & debug_mask) != 0 ||
      reply.report_size < sizeof(VBS_ENCLAVE_REPORT_PKG_HEADER) +
                              sizeof(VBS_ENCLAVE_REPORT) ||
      reply.report_size > kMaxReportBytes) return false;
  // Bounds and nonce checks only. This does not authenticate an enclave to a
  // remote client; local verification was performed INSIDE the enclave.
  VBS_ENCLAVE_REPORT_PKG_HEADER package{};
  memcpy(&package, reply.report, sizeof(package));
  if (package.Version != VBS_ENCLAVE_REPORT_PKG_HEADER_VERSION_CURRENT ||
      package.PackageSize != reply.report_size ||
      package.SignedStatementSize < sizeof(VBS_ENCLAVE_REPORT) ||
      package.SignedStatementSize > reply.report_size - sizeof(package) ||
      package.SignatureSize != reply.report_size - sizeof(package) -
                                    package.SignedStatementSize) return false;
  VBS_ENCLAVE_REPORT report{};
  memcpy(&report, reply.report + sizeof(package), sizeof(report));
  return report.ReportVersion == VBS_ENCLAVE_REPORT_VERSION_CURRENT &&
      report.ReportSize >= sizeof(report) &&
      report.ReportSize <= package.SignedStatementSize &&
      report.EnclaveIdentity.EnclaveType == ENCLAVE_TYPE_VBS &&
      (report.EnclaveIdentity.Flags & debug_mask) == 0 &&
      memcmp(report.EnclaveData, exchange.request.challenge, 32) == 0 &&
      memcmp(report.EnclaveData + 32, reply.random_commitment, 32) == 0;
}
}  // namespace

int wmain(int argc, wchar_t** argv) {
  Result result;
  result.supported = IsEnclaveTypeSupported(ENCLAVE_TYPE_VBS) != FALSE;
  if (argc == 2 && wcscmp(argv[1], L"--support-only") == 0) {
    Emit(result);
    return result.supported ? 0 : 10;
  }
  if (argc < 2 || argc > 3) {
    fputs("Usage: probe_host.exe ENCLAVE_DLL [REPORT_OUTPUT]\n", stderr);
    return 2;
  }
  if (!result.supported) { Emit(result); return 10; }

  ENCLAVE_CREATE_INFO_VBS create_info{};  // Flags=0: non-debug.
  memcpy(create_info.OwnerID, "hintless-vbs-local-probe-v1", 27);
  result.stage = "CreateEnclave";
  void* enclave = CreateEnclave(GetCurrentProcess(), nullptr,
      kProbeEnclaveSize, 0, ENCLAVE_TYPE_VBS, &create_info,
      sizeof(create_info), nullptr);
  if (!enclave) {
    result.error = GetLastError(); Emit(result); return 11;
  }
  result.created = true;
  int exit_code = 12;
  do {
    result.stage = "LoadEnclaveImageW";
    DWORD previous_mode = 0;
    SetThreadErrorMode(GetThreadErrorMode() | SEM_FAILCRITICALERRORS,
                       &previous_mode);
    BOOL loaded = LoadEnclaveImageW(enclave, argv[1]);
    DWORD load_error = loaded ? ERROR_SUCCESS : GetLastError();
    SetThreadErrorMode(previous_mode, nullptr);
    if (!loaded) { result.error = load_error; break; }
    result.loaded = true;
    result.stage = "InitializeEnclave";
    exit_code = 13;
    ENCLAVE_INIT_INFO_VBS init{sizeof(init), 1};
    if (!InitializeEnclave(GetCurrentProcess(), enclave, &init,
                          sizeof(init), nullptr)) {
      result.error = GetLastError(); break;
    }
    result.initialized = true;
    result.stage = "GetProcAddress";
    exit_code = 14;
    auto routine = reinterpret_cast<LPENCLAVE_ROUTINE>(
        GetProcAddress(static_cast<HMODULE>(enclave), "HintlessVbsProbe"));
    if (!routine) { result.error = GetLastError(); break; }
    ProbeExchange exchange{};
    exchange.request.version = kProbeVersion;
    exchange.request.size = sizeof(exchange.request);
    NTSTATUS status = BCryptGenRandom(nullptr, exchange.request.challenge, 32,
                                      BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status < 0) { result.operation_status = HRESULT_FROM_NT(status); break; }
    result.stage = "CallEnclave";
    exit_code = 15;
    void* returned = nullptr;
    if (!CallEnclave(routine, &exchange, TRUE, &returned)) {
      result.error = GetLastError(); break;
    }
    result.called = true;
    result.operation_status = static_cast<HRESULT>(reinterpret_cast<ULONG_PTR>(returned));
    if (FAILED(result.operation_status)) break;
    result.operation_status = exchange.reply.operation_status;
    result.local_verification = exchange.reply.local_report_verification;
    result.identity_flags = exchange.reply.identity_flags;
    result.attested_keys = exchange.reply.uses_attested_keys;
    result.crypto_checks = exchange.reply.crypto_checks_passed;
    result.report_bytes = exchange.reply.report_size;
    result.stage = "ValidateReportBinding";
    exit_code = 16;
    result.checked = CheckReport(exchange);
    if (!result.checked) break;
    if (argc == 3) {
      result.stage = "SaveReport";
      FILE* output = nullptr;
      if (_wfopen_s(&output, argv[2], L"wb") != 0 || !output) break;
      result.report_saved = fwrite(exchange.reply.report, 1,
          exchange.reply.report_size, output) == exchange.reply.report_size;
      if (fclose(output) != 0) result.report_saved = false;
      if (!result.report_saved) break;
    }
    result.stage = "RejectMalformedInput";
    exchange.request.version = kProbeVersion + 1;
    returned = nullptr;
    result.malformed_rejected = CallEnclave(routine, &exchange, TRUE, &returned) &&
        static_cast<HRESULT>(reinterpret_cast<ULONG_PTR>(returned)) == E_INVALIDARG;
    if (!result.malformed_rejected) break;
    returned = nullptr;
    result.null_rejected = CallEnclave(routine, nullptr, TRUE, &returned) &&
        FAILED(static_cast<HRESULT>(reinterpret_cast<ULONG_PTR>(returned)));
    if (!result.null_rejected) break;
    result.stage = "complete";
    exit_code = 0;
  } while (false);
  if (result.initialized && !TerminateEnclave(enclave, TRUE))
    result.cleanup_error = GetLastError();
  result.deleted = DeleteEnclave(enclave) != FALSE;
  if (!result.deleted && !result.cleanup_error) result.cleanup_error = GetLastError();
  if (exit_code == 0 && result.cleanup_error) exit_code = 17;
  Emit(result);
  return exit_code;
}
