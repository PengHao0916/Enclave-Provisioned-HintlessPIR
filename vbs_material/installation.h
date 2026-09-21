#ifndef HINTLESS_VBS_INSTALLATION_H_
#define HINTLESS_VBS_INSTALLATION_H_
#include "rlwe_material.h"

namespace hintless_vbs {
// Fixed x64 little-endian ABI. All identity/digest fields are 32 raw bytes.
struct InstallationBinding {
  BYTE configuration_id[32];
  BYTE material_id[32];
  BYTE material_digest[32];
  BYTE generation_receipt_digest[32];
  BYTE client_nonce[32];
  BYTE server_epoch[32];
};
struct InstallationAck {
  ULONG version;
  ULONG size;
  InstallationBinding binding;
  BYTE signature[64];  // ECDSA P-256: fixed-width big-endian r || s.
};
constexpr char kInstallationDomain[] = "HintlessPIR/installed-ack/P256-SHA256/v1";
static_assert(sizeof(InstallationBinding) == 192, "Unexpected installation binding");
static_assert(sizeof(InstallationAck) == 264, "Unexpected installation acknowledgement");
// Authentication of a pinned server's statement, NOT proof of honest storage.
HRESULT VerifyInstallationAck(const InstallationAck& ack, const BYTE pinned_key[65]);
}  // namespace hintless_vbs
#endif
