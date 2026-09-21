#include "installation_server.h"
#include <cstring>
#include <stddef.h>
#include "openssl/bn.h"
#include "openssl/crypto.h"
#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "openssl/nid.h"
#include "openssl/rand.h"
#include "shell_encryption/montgomery.h"
#include "shell_encryption/rns/rns_context.h"
#include "shell_encryption/rns/rns_polynomial.h"
#include "shell_encryption/status_macros.h"

namespace hintless_pir::vbs {
namespace {
using Mod = rlwe::MontgomeryInt<rlwe::Uint64>;
using Context = rlwe::RnsContext<Mod>;
using Poly = rlwe::RnsPolynomial<Mod>;
namespace lm = local_material;
namespace wire = hintless_vbs;
bool Equal(const void* a, const void* b, size_t n) { return CRYPTO_memcmp(a, b, n) == 0; }
absl::StatusOr<rlwe::SerializedRnsPolynomial> Serialize(const uint64_t values[2][4096], const Context& context) {
  auto moduli = context.MainPrimeModuli();
  std::vector<std::vector<Mod>> vectors(2);
  for (int q = 0; q < 2; ++q) for (int i = 0; i < 4096; ++i) {
    if (values[q][i] >= wire::kCiphertextModuli[q]) return absl::InvalidArgumentError("Non-canonical coefficient.");
    RLWE_ASSIGN_OR_RETURN(auto v, Mod::ImportInt(values[q][i], moduli[q]->ModParams()));
    vectors[q].push_back(v);
  }
  RLWE_ASSIGN_OR_RETURN(auto poly, Poly::Create(std::move(vectors), true));
  return poly.Serialize(moduli);
}
}  // namespace

absl::StatusOr<std::unique_ptr<AuthenticatedInstaller>> AuthenticatedInstaller::Create(
    lm::Parameters params, lm::PreparedServer* server) {
  if (!server || params.linpir_params.log_n != 12 || params.linpir_params.qs.size() != 2 ||
      params.linpir_params.qs[0] != wire::kCiphertextModuli[0] ||
      params.linpir_params.qs[1] != wire::kCiphertextModuli[1] ||
      params.linpir_params.ts.size() < 2 || params.linpir_params.ts.size() > 3)
    return absl::InvalidArgumentError("Installer requires a supported raw-material profile.");
  auto result = std::unique_ptr<AuthenticatedInstaller>(new AuthenticatedInstaller(std::move(params), server));
  result->key_.reset(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
  if (!result->key_ || EC_KEY_generate_key(result->key_.get()) != 1 ||
      EC_POINT_point2oct(EC_KEY_get0_group(result->key_.get()), EC_KEY_get0_public_key(result->key_.get()),
          POINT_CONVERSION_UNCOMPRESSED, result->public_key_.data(), 65, nullptr) != 65 ||
      RAND_bytes(result->epoch_.data(), 32) != 1) return absl::InternalError("Server signing key generation failed.");
  return result;
}

absl::StatusOr<wire::InstallationAck> AuthenticatedInstaller::Install(
    const wire::RawMaterial& raw, const wire::InstallationBinding& binding) {
  std::lock_guard<std::mutex> lock(mutex_);
  const auto config = lm::ConfigurationId(params_, server_->PublicParams());
  const auto digest = lm::Digest(absl::string_view(reinterpret_cast<const char*>(&raw), sizeof(raw)));
  if (raw.version != 1 || raw.plaintext_limbs != params_.linpir_params.ts.size() ||
      !Equal(raw.configuration_id, config.data(), 32) ||
      !Equal(raw.configuration_id, binding.configuration_id, 32) ||
      !Equal(raw.material_id, binding.material_id, 32) ||
      !Equal(digest.data(), binding.material_digest, 32) ||
      !Equal(epoch_.data(), binding.server_epoch, 32)) return absl::InvalidArgumentError("Installation binding mismatch.");
  const std::string id(reinterpret_cast<const char*>(raw.material_id), 32);
  auto found = installed_.find(id);
  if (found != installed_.end()) {
    if (!Equal(&found->second.binding, &binding, sizeof(binding))) return absl::AlreadyExistsError("Installation ID reused with changed binding.");
    return found->second;  // Receipt of the original installation, not a fresh READY assertion.
  }
  for (unsigned t = raw.plaintext_limbs; t < 3; ++t)
    for (unsigned q = 0; q < 2; ++q) for (unsigned i = 0; i < 4096; ++i)
      if (raw.ciphertext_b[t][q][i]) return absl::InvalidArgumentError("Unused CRT branch must be zero.");
  RLWE_ASSIGN_OR_RETURN(auto context, Context::CreateForBfvFiniteFieldEncoding(
      12, params_.linpir_params.qs, {}, params_.linpir_params.ts[0]));
  lm::Material material;
  material.set_config_id(config); material.set_material_id(id);
  for (unsigned t = 0; t < raw.plaintext_limbs; ++t) {
    RLWE_ASSIGN_OR_RETURN(*material.add_ciphertexts(), Serialize(raw.ciphertext_b[t], context));
  }
  for (unsigned r = 0; r < 6; ++r) {
    RLWE_ASSIGN_OR_RETURN(*material.add_galois_key(), Serialize(raw.galois_b[r], context));
  }
  // Sign ONLY after the actual PIR server accepted and installed this material.
  RLWE_ASSIGN_OR_RETURN(auto ignored_receipt, server_->Install(material));
  wire::InstallationAck ack{};
  ack.version = 1; ack.size = sizeof(ack); ack.binding = binding;
  std::string message(wire::kInstallationDomain, sizeof(wire::kInstallationDomain) - 1);
  message.append(reinterpret_cast<const char*>(&ack), offsetof(wire::InstallationAck, signature));
  const auto hash = lm::Digest(message);
  bssl::UniquePtr<ECDSA_SIG> signature(ECDSA_do_sign(
      reinterpret_cast<const uint8_t*>(hash.data()), hash.size(), key_.get()));
  if (!signature || BN_bn2bin_padded(ack.signature, 32, ECDSA_SIG_get0_r(signature.get())) != 1 ||
      BN_bn2bin_padded(ack.signature + 32, 32, ECDSA_SIG_get0_s(signature.get())) != 1) {
    auto status = server_->Release(id);
    (void)status;
    return absl::InternalError("Installation signing failed; material invalidated.");
  }
  installed_.emplace(id, ack);
  return ack;
}
}  // namespace hintless_pir::vbs
