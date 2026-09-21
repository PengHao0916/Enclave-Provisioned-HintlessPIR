#pragma once
#include "material_test_abi.h"
#include "installation.h"

namespace hintless_vbs {
// PUBLIC FIXTURES ONLY. The test runner provisions the server key out of band.
// This framing is not a production trust bootstrap or network endpoint.
struct PublicLifecycleInput {
  PublicMaterialTestRequest request;
  BYTE pinned_server_key[65];
  BYTE server_epoch[32];
  BYTE reserved[3];
};
static_assert(sizeof(PublicLifecycleInput) == 404);
}  // namespace hintless_vbs
