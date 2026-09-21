#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "material_test_abi.h"
#include "probe_abi.h"

namespace {
struct Enclave {
  void* address = nullptr;
  bool initialized = false;
  ~Enclave() {
    if (initialized) TerminateEnclave(address, TRUE);
    if (address) DeleteEnclave(address);
  }
};
HRESULT RunInEnclave(const wchar_t* dll, hintless_vbs::PublicMaterialTestExchange* exchange,
                     const char*& stage) {
  stage = "IsEnclaveTypeSupported";
  if (!IsEnclaveTypeSupported(ENCLAVE_TYPE_VBS)) return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
  ENCLAVE_CREATE_INFO_VBS create{}; // No debug.
  Enclave enclave;
  stage = "CreateEnclave";
  enclave.address = CreateEnclave(GetCurrentProcess(), nullptr, kProbeEnclaveSize,
                                  0, ENCLAVE_TYPE_VBS, &create, sizeof(create), nullptr);
  if (!enclave.address) return HRESULT_FROM_WIN32(GetLastError());
  DWORD previous = 0;
  SetThreadErrorMode(GetThreadErrorMode() | SEM_FAILCRITICALERRORS, &previous);
  stage = "LoadEnclaveImageW";
  BOOL loaded = LoadEnclaveImageW(enclave.address, dll);
  DWORD load_error = loaded ? ERROR_SUCCESS : GetLastError();
  SetThreadErrorMode(previous, nullptr);
  if (!loaded) return HRESULT_FROM_WIN32(load_error);
  ENCLAVE_INIT_INFO_VBS init{sizeof(init), 1};
  stage = "InitializeEnclave";
  if (!InitializeEnclave(GetCurrentProcess(), enclave.address, &init, sizeof(init), nullptr))
    return HRESULT_FROM_WIN32(GetLastError());
  enclave.initialized = true;
  stage = "GetProcAddress";
  auto routine = reinterpret_cast<LPENCLAVE_ROUTINE>(GetProcAddress(
      static_cast<HMODULE>(enclave.address), "HintlessPublicMaterialTest"));
  if (!routine) return HRESULT_FROM_WIN32(GetLastError());
  void* returned = nullptr;
  stage = "CallEnclave";
  if (!CallEnclave(routine, exchange, TRUE, &returned)) return HRESULT_FROM_WIN32(GetLastError());
  return static_cast<HRESULT>(reinterpret_cast<ULONG_PTR>(returned));
}
}  // namespace

int wmain(int argc, wchar_t** argv) {
  using namespace hintless_vbs;
  const bool native = argc == 4 && wcscmp(argv[1], L"--native") == 0;
  const bool enclave = argc == 5 && wcscmp(argv[1], L"--enclave") == 0;
  if (!native && !enclave) {
    fputs("Usage: material_test_host --native REQUEST OUTPUT\n"
          "       material_test_host --enclave DLL REQUEST OUTPUT\n"
          "PUBLIC TEST SECRETS ONLY. NOT A PRIVATE QUERY SERVICE.\n", stderr);
    return 2;
  }
  auto* exchange = static_cast<PublicMaterialTestExchange*>(
      HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PublicMaterialTestExchange)));
  if (!exchange) return 3;
  HRESULT hr = E_FAIL;
  bool success = false;
  const char* stage = "ReadRequest";
  do {
    FILE* input = nullptr;
    if (_wfopen_s(&input, argv[argc - 2], L"rb") || !input) break;
    const bool valid_size = fread(&exchange->request, 1, sizeof(exchange->request), input) == sizeof(exchange->request) && fgetc(input) == EOF;
    fclose(input);
    stage = "ValidateRequest";
    if (!valid_size || exchange->request.version != 1 ||
        exchange->request.size != sizeof(exchange->request) || exchange->request.case_index > 255) {
      hr = E_INVALIDARG; break;
    }
    if (native) {
      stage = "GenerateMaterial";
      BYTE master[32], id[32];
      PublicTestSecrets(exchange->request.case_index, master, id);
      hr = GenerateMaterial(exchange->request.config, id, master, &exchange->material);
      SecureZeroMemory(master, sizeof(master));
    } else {
      hr = RunInEnclave(argv[2], exchange, stage);
    }
    if (FAILED(hr)) break;
    FILE* output = nullptr;
    stage = "WriteMaterial";
    if (_wfopen_s(&output, argv[argc - 1], L"wb") || !output) { hr = E_FAIL; break; }
    success = fwrite(&exchange->material, 1, sizeof(exchange->material), output) == sizeof(exchange->material);
    if (fclose(output)) success = false;
    if (!success) hr = E_FAIL;
    if (success) stage = "complete";
  } while (false);
  SecureZeroMemory(exchange, sizeof(*exchange));
  HeapFree(GetProcessHeap(), 0, exchange);
  printf("{\"backend\":\"%s\",\"public_test_secrets_only\":true,\"success\":%s,\"stage\":\"%s\",\"hresult\":\"0x%08lX\"}\n",
      native ? "native-material-test-NOT-TEE" : "vbs-enclave-public-material-test",
      success ? "true" : "false", stage, static_cast<ULONG>(hr));
  return success ? 0 : 1;
}
