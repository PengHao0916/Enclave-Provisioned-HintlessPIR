#ifndef HINTLESS_VBS_PROBE_ABI_H_
#define HINTLESS_VBS_PROBE_ABI_H_

#include <windows.h>

// A diagnostic ABI only. It deliberately accepts no PIR seed or query index.
// A successful probe is NOT an implementation of MaterialGenerator.
constexpr ULONG kProbeVersion = 3;
constexpr SIZE_T kProbeEnclaveSize = 16 * 1024 * 1024;
constexpr ULONG kMaxReportBytes = 16 * 1024;

struct ProbeRequest {
  ULONG version;
  ULONG size;
  BYTE challenge[32];
};

struct ProbeReply {
  ULONG version;
  ULONG size;
  HRESULT operation_status;
  ULONG enclave_type;
  ULONG identity_flags;
  ULONG signing_level;
  ULONG uses_attested_keys;
  HRESULT local_report_verification;
  ULONG report_size;
  ULONG crypto_checks_passed;
  BYTE random_commitment[32];
  BYTE report[kMaxReportBytes];
};

struct ProbeExchange {
  ProbeRequest request;
  ProbeReply reply;
};

static_assert(sizeof(ProbeRequest) == 40, "Unexpected probe ABI layout");
static_assert(sizeof(ProbeReply) == 16456, "Unexpected reply ABI layout");
#endif
