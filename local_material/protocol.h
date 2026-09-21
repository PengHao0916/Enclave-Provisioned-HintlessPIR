#ifndef HINTLESS_PIR_LOCAL_MATERIAL_PROTOCOL_H_
#define HINTLESS_PIR_LOCAL_MATERIAL_PROTOCOL_H_

#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "absl/status/statusor.h"
#include "hintless_simplepir/client.h"
#include "hintless_simplepir/server.h"
#include "local_material/serialization.pb.h"

namespace hintless_pir::local_material {

using Parameters = hintless_simplepir::Parameters;
inline constexpr char kBackend[] = "local-simulation-NOT-TEE";

absl::Status ValidateParameters(const Parameters& params);
std::string ConfigurationId(const Parameters& params,
                            const HintlessPirServerPublicParams& public_params);
GeneratorConfig MakeGeneratorConfig(
    const Parameters& params, const HintlessPirServerPublicParams& public_params);
std::string Digest(absl::string_view bytes);
absl::StatusOr<std::string> RandomId();
absl::StatusOr<std::string> DeriveSeed(
    const Preparation& prep, absl::string_view purpose, rlwe::PrngType type);

// This interface has no database, query index or recovery method. Replacing
// the backend requires actual attestation, an end-to-end private channel,
// and an audited erasure implementation. This class supplies none of those.
class MaterialGenerator {
 public:
  virtual ~MaterialGenerator() = default;
  virtual absl::StatusOr<Material> Generate(const Preparation& prep) const = 0;
};

class LocalMaterialGenerator final : public MaterialGenerator {
 public:
  LocalMaterialGenerator(Parameters params, GeneratorConfig config)
      : params_(std::move(params)), config_(std::move(config)) {}
  absl::StatusOr<Material> Generate(const Preparation& prep) const override;
 private:
  Parameters params_;
  GeneratorConfig config_;
};

enum class State { kPending, kReady, kReserved, kInFlight, kDone, kInvalid };

// In-memory state only. No resume/import API: restart abandons every old
// material. Concurrent calls are serialized; this is not a throughput claim.
class PreparedClient {
 public:
  static absl::StatusOr<std::unique_ptr<PreparedClient>> Create(
      Parameters params, HintlessPirServerPublicParams public_params);
  ~PreparedClient();
  absl::StatusOr<Preparation> BeginPreparation();
  // Both receipts must match. They are unauthenticated simulation receipts.
  absl::Status AcceptReady(const Receipt& generated, const Receipt& installed);
  absl::StatusOr<Query> GenerateQuery(absl::string_view material_id, int64_t index);
  absl::StatusOr<Query> Retry(absl::string_view material_id) const;
  absl::StatusOr<std::string> Recover(const Response& response);
  absl::Status Abandon(absl::string_view material_id);
  absl::StatusOr<State> GetState(absl::string_view material_id) const;
 private:
  PreparedClient(Parameters params, HintlessPirServerPublicParams pub)
      : params_(std::move(params)), public_params_(std::move(pub)),
        config_id_(ConfigurationId(params_, public_params_)) {}
  struct Entry {
    std::string seed;
    State state = State::kPending;
    Query request;
    std::unique_ptr<hintless_simplepir::Client> recovery;
  };
  void Forget(Entry& entry);
  Parameters params_;
  HintlessPirServerPublicParams public_params_;
  std::string config_id_;
  std::map<std::string, Entry> entries_;
  mutable std::mutex mutex_;
};

Receipt MakeReceipt(const Material& material);

class PreparedServer {
 public:
  static absl::StatusOr<std::unique_ptr<PreparedServer>> Create(Parameters params);
  HintlessPirServerPublicParams PublicParams() const;
  absl::StatusOr<Receipt> Install(const Material& material);
  absl::StatusOr<Response> Handle(const Query& query);
  // Deletes the response cache but preserves a consumed-material tombstone.
  absl::Status Release(absl::string_view material_id);
  // Quiescent database update: fresh public configuration invalidates all IDs.
  absl::Status Refresh();
  // Test oracle only; not exposed as a deployment endpoint.
  absl::StatusOr<std::string> ExpectedRecord(int64_t index) const;
 private:
  PreparedServer(Parameters params, std::unique_ptr<hintless_simplepir::Server> core)
      : params_(std::move(params)), core_(std::move(core)) {}
  struct Entry {
    State state = State::kReady;
    Material material;
    std::string request_bytes;
    Response response;
  };
  Parameters params_;
  std::unique_ptr<hintless_simplepir::Server> core_;
  std::string config_id_;
  std::map<std::string, Entry> entries_;
  mutable std::mutex mutex_;
};

// Functional profile, deliberately not an asserted security parameter set.
Parameters DemoParameters();
absl::StatusOr<Parameters> ParametersForProfile(absl::string_view profile);

}  // namespace hintless_pir::local_material
#endif
