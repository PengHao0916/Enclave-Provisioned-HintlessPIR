#pragma once
#include <string>
#include "installation_server.h"
#include "lifecycle_test_abi.h"

namespace hintless_pir::vbs {
// PUBLIC FIXTURE integration helper, never a production client transport.
// corruption: 0 valid, 1 signature, 2 nonce, 3 malformed pinned key, 4 version.
absl::Status RunPublicLifecycle(const std::string& program, const std::string& dll,
    const std::string& log, const hintless_vbs::PublicMaterialTestRequest& request,
    AuthenticatedInstaller& installer, hintless_vbs::RawMaterial& raw, int corruption = 0);

// Research-only local client transport with a fresh non-public seed. The seed
// is sent to the logical client helper over a pipe and is never included in the
// public material returned to the ordinary PIR server.
absl::Status RunPrivateResearchLifecycle(const std::string& program, const std::string& dll,
    const std::string& log, const hintless_vbs::PrivateResearchMaterialRequest& request,
    AuthenticatedInstaller& installer, hintless_vbs::RawMaterial& raw,
    hintless_vbs::PrivateResearchLifecycleMetrics& metrics);
}  // namespace hintless_pir::vbs
