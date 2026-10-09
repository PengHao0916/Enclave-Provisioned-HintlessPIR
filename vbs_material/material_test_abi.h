#ifndef HINTLESS_VBS_MATERIAL_TEST_ABI_H_
#define HINTLESS_VBS_MATERIAL_TEST_ABI_H_
#include "rlwe_material.h"
namespace hintless_vbs {
// Diagnostic only: public, deterministic master seeds. This ABI can never
// provision a private client secret and must never serve production queries.
struct PublicMaterialTestRequest {
  ULONG version;
  ULONG size;
  ULONG case_index;
  MaterialConfig config;
};
struct PublicMaterialTestExchange {
  PublicMaterialTestRequest request;
  RawMaterial material;
};

// Research-only client input. The caller represents the client and supplies a
// fresh random seed over an inherited pipe; the seed is never written to the
// material output or accepted by an enclave export in plaintext. This is a
// local functional-validation transport, not a production network protocol.
struct PrivateResearchMaterialRequest {
  ULONG version;
  ULONG size;
  MaterialConfig config;
  BYTE material_id[32];
  BYTE master_seed[32];
  BYTE challenge[32];
};
inline void PublicTestSecrets(ULONG index, BYTE master[32], BYTE id[32]) {
  for (ULONG i = 0; i < 32; ++i) {
    master[i] = static_cast<BYTE>(i + 17 * index);
    id[i] = static_cast<BYTE>(255 - i - 19 * index);
  }
}
static_assert(sizeof(PublicMaterialTestRequest) == 304, "Unexpected test request ABI");
static_assert(sizeof(PrivateResearchMaterialRequest) == 396,
              "Unexpected private research request ABI");
}  // namespace hintless_vbs
#endif
