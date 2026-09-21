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
inline void PublicTestSecrets(ULONG index, BYTE master[32], BYTE id[32]) {
  for (ULONG i = 0; i < 32; ++i) {
    master[i] = static_cast<BYTE>(i + 17 * index);
    id[i] = static_cast<BYTE>(255 - i - 19 * index);
  }
}
static_assert(sizeof(PublicMaterialTestRequest) == 304, "Unexpected test request ABI");
}  // namespace hintless_vbs
#endif
