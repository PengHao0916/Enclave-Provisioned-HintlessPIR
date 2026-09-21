#ifndef HINTLESS_VBS_INSTALLATION_SERVER_H_
#define HINTLESS_VBS_INSTALLATION_SERVER_H_
#include <array>
#include <map>
#include <memory>
#include <mutex>
#include "installation.h"
#include "local_material/protocol.h"
#include "openssl/base.h"
#include "openssl/ec_key.h"

namespace hintless_pir::vbs {
class AuthenticatedInstaller final {
 public:
  static absl::StatusOr<std::unique_ptr<AuthenticatedInstaller>> Create(
      local_material::Parameters params, local_material::PreparedServer* server);
  absl::StatusOr<hintless_vbs::InstallationAck> Install(
      const hintless_vbs::RawMaterial& raw, const hintless_vbs::InstallationBinding& binding);
  const std::array<uint8_t, 65>& PublicKey() const { return public_key_; }
  const std::array<uint8_t, 32>& Epoch() const { return epoch_; }
 private:
  AuthenticatedInstaller(local_material::Parameters params, local_material::PreparedServer* server)
      : params_(std::move(params)), server_(server) {}
  local_material::Parameters params_;
  local_material::PreparedServer* server_;  // Caller owns this; must outlive us.
  bssl::UniquePtr<EC_KEY> key_;
  std::array<uint8_t, 65> public_key_{};
  std::array<uint8_t, 32> epoch_{};
  std::map<std::string, hintless_vbs::InstallationAck> installed_;
  std::mutex mutex_;
};
}  // namespace hintless_pir::vbs
#endif
