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

// PrivateResearchMaterialRequest is delivered only to the logical client test
// process over a pipe. The ordinary PIR server receives RawMaterial below and
// never receives master_seed.
struct PrivateResearchLifecycleInput {
  PrivateResearchMaterialRequest request;
  BYTE pinned_server_key[65];
  BYTE server_epoch[32];
  BYTE reserved[3];
};

struct PrivateResearchLifecycleMetrics {
  ULONG version;
  ULONG size;
  uint64_t enclave_load_ns;
  uint64_t channel_begin_ns;
  uint64_t client_seal_ns;
  uint64_t enclave_generate_ns;
  uint64_t receipt_accept_ns;
  uint64_t installation_roundtrip_ns;
  uint64_t total_ns;
};

static_assert(sizeof(PrivateResearchLifecycleInput) == 496);
static_assert(sizeof(PrivateResearchLifecycleMetrics) == 64);
}  // namespace hintless_vbs
