#include "local_material/protocol.h"

#include <iomanip>
#include <limits>
#include <locale>
#include <sstream>

#include "absl/strings/str_cat.h"
#include "hintless_simplepir/utils.h"
#include "lwe/lwe_symmetric_encryption.h"
#include "openssl/crypto.h"
#include "openssl/digest.h"
#include "openssl/hkdf.h"
#include "openssl/rand.h"
#include "openssl/sha.h"
#include "shell_encryption/int256.h"
#include "shell_encryption/prng/single_thread_chacha_prng.h"
#include "shell_encryption/prng/single_thread_hkdf_prng.h"
#include "shell_encryption/status_macros.h"

namespace hintless_pir::local_material {
namespace {
using RI = Parameters::RlweInteger;
using MI = rlwe::MontgomeryInt<RI>;
using Context = rlwe::RnsContext<MI>;
using LinClient = linpir::Client<RI>;

void Wipe(std::string& bytes) {
  if (!bytes.empty()) OPENSSL_cleanse(&bytes[0], bytes.size());
  bytes.clear();
}
struct Seed {
  std::string value;
  ~Seed() { Wipe(value); }
};
template <typename Message>
void ReleaseStorage(Message& message) {
  Message empty;
  message.Swap(&empty);
}
absl::Status CheckPolynomial(const rlwe::SerializedRnsPolynomial& poly,
                              const Parameters& params) {
  if (poly.log_n() != params.linpir_params.log_n || !poly.is_ntt() ||
      poly.coeff_vectors_size() != params.linpir_params.qs.size()) {
    return absl::InvalidArgumentError("Malformed polynomial shape.");
  }
  for (const auto& coefficients : poly.coeff_vectors()) {
    if (coefficients.empty()) return absl::InvalidArgumentError("Empty polynomial coefficients.");
  }
  return absl::OkStatus();
}
absl::Status CheckResponse(const HintlessPirResponse& response, const Parameters& params) {
  const int shards = hintless_simplepir::DivAndRoundUp(params.db_record_bit_size, params.lwe_plaintext_bit_size);
  const int blocks = hintless_simplepir::DivAndRoundUp<int64_t>(params.db_rows, params.linpir_params.rows_per_block);
  if (response.ct_records_size() != shards || response.linpir_responses_size() != params.linpir_params.ts.size()) {
    return absl::InvalidArgumentError("Malformed response dimensions.");
  }
  for (const auto& record : response.ct_records()) {
    if (record.b_coeffs_size() != params.db_rows) return absl::InvalidArgumentError("Malformed LWE response.");
  }
  for (const auto& limb : response.linpir_responses()) {
    if (limb.ct_inner_products_size() != shards) return absl::InvalidArgumentError("Malformed CRT limb.");
    for (const auto& shard : limb.ct_inner_products()) {
      if (shard.ct_b_blocks_size() != blocks) return absl::InvalidArgumentError("Malformed response blocks.");
      for (const auto& block : shard.ct_b_blocks()) {
        RLWE_RETURN_IF_ERROR(CheckPolynomial(block, params));
      }
    }
  }
  return absl::OkStatus();
}
absl::StatusOr<std::unique_ptr<rlwe::SecurePrng>> Prng(
    rlwe::PrngType type, absl::string_view seed) {
  if (type == rlwe::PRNG_TYPE_HKDF) {
    RLWE_ASSIGN_OR_RETURN(auto p, rlwe::SingleThreadHkdfPrng::Create(seed));
    return std::unique_ptr<rlwe::SecurePrng>(std::move(p));
  }
  if (type == rlwe::PRNG_TYPE_CHACHA) {
    RLWE_ASSIGN_OR_RETURN(auto p, rlwe::SingleThreadChaChaPrng::Create(seed));
    return std::unique_ptr<rlwe::SecurePrng>(std::move(p));
  }
  return absl::InvalidArgumentError("Unsupported PRNG.");
}
bool IsId(absl::string_view id) { return id.size() == 32; }
// Legacy core messages declare client_id as UTF-8 string, whereas material
// IDs are random bytes. Hex encoding keeps the compatibility adapter valid.
std::string SessionId(absl::string_view id) {
  const char* hex = "0123456789abcdef";
  std::string encoded;
  encoded.reserve(2 * id.size());
  for (unsigned char byte : id) {
    encoded.push_back(hex[byte >> 4]);
    encoded.push_back(hex[byte & 15]);
  }
  return encoded;
}
void Append(std::string& out, absl::string_view field) {
  uint64_t length = field.size();
  for (int i = 7; i >= 0; --i) out.push_back((length >> (i * 8)) & 255);
  out.append(field.data(), field.size());
}
absl::Status ValidatePublic(const Parameters& params,
                            const HintlessPirServerPublicParams& pub) {
  RLWE_RETURN_IF_ERROR(ValidateParameters(params));
  if (pub.pool_capacity() != 1 || pub.pool_epoch() == 0 ||
      pub.database_version().empty() ||
      pub.prng_seed_linpir_ct_pads_size() != params.linpir_params.ts.size() ||
      pub.linpir_response_hints_size() != params.linpir_params.ts.size()) {
    return absl::InvalidArgumentError("Expected one versioned static response set.");
  }
  return absl::OkStatus();
}
}  // namespace

absl::Status ValidateParameters(const Parameters& p) {
  const auto& r = p.linpir_params;
  if (p.db_rows <= 0 || p.db_cols <= 0 || p.db_cols % 2 != 0 ||
      p.db_rows > std::numeric_limits<int>::max() ||
      p.db_cols > std::numeric_limits<int>::max() ||
      p.db_record_bit_size <= 0 || p.db_record_bit_size % 8 != 0 ||
      p.lwe_modulus_bit_size != 32 || p.lwe_plaintext_bit_size < 1 ||
      p.lwe_plaintext_bit_size > 8 || p.lwe_error_variance != 8 ||
      p.session_pool_capacity != 1 || r.log_n < 4 || r.log_n > 16 ||
      p.lwe_secret_dim <= 0 || p.lwe_secret_dim > (1 << (r.log_n - 1)) ||
      r.rows_per_block < 2 || r.rows_per_block > (1 << (r.log_n - 1)) ||
      (r.rows_per_block & (r.rows_per_block - 1)) != 0 ||
      r.qs.empty() || r.ts.empty() || r.ts.size() > 3 ||
      r.gadget_log_bs.size() != r.qs.size() || r.error_variance <= 0 ||
      !(p.prng_type == rlwe::PRNG_TYPE_HKDF || p.prng_type == rlwe::PRNG_TYPE_CHACHA) ||
      !(r.prng_type == rlwe::PRNG_TYPE_HKDF || r.prng_type == rlwe::PRNG_TYPE_CHACHA)) {
    return absl::InvalidArgumentError("Unsupported local material parameters.");
  }
  // With ternary s and balanced H, |Hs| <= n*2^31. This is only the
  // deterministic CRT range check, not an LWE/RLWE security/noise estimate.
  rlwe::uint256 product = 1;
  for (RI t : r.ts) {
    if (t < 3) return absl::InvalidArgumentError("Invalid CRT modulus.");
    product *= t;
  }
  if (product <= (rlwe::uint256(p.lwe_secret_dim) << 32)) {
    return absl::InvalidArgumentError("CRT product must exceed n * 2^32 for ternary s.");
  }
  return absl::OkStatus();
}

std::string Digest(absl::string_view bytes) {
  std::string result(SHA256_DIGEST_LENGTH, '\0');
  SHA256(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size(),
         reinterpret_cast<uint8_t*>(&result[0]));
  return result;
}

std::string ConfigurationId(const Parameters& p,
                            const HintlessPirServerPublicParams& pub) {
  std::ostringstream desc;
  desc.imbue(std::locale::classic());
  desc << std::setprecision(17) << "local-material-v1 " << p.db_rows << ' '
       << p.db_cols << ' ' << p.db_record_bit_size << ' ' << p.lwe_secret_dim
       << ' ' << p.lwe_modulus_bit_size << ' ' << p.lwe_plaintext_bit_size
       << ' ' << p.lwe_error_variance << ' ' << p.prng_type << ' '
       << p.session_pool_capacity << ' ' << p.linpir_params.log_n << ' '
       << p.linpir_params.rows_per_block << ' ' << p.linpir_params.error_variance
       << ' ' << p.linpir_params.prng_type;
  desc << " q"; for (auto q : p.linpir_params.qs) desc << ' ' << q;
  desc << " t"; for (auto t : p.linpir_params.ts) desc << ' ' << t;
  desc << " b"; for (auto b : p.linpir_params.gadget_log_bs) desc << ' ' << b;
  std::string binding;
  Append(binding, desc.str());
  Append(binding, pub.SerializeAsString());
  return Digest(binding);
}

GeneratorConfig MakeGeneratorConfig(
    const Parameters& params, const HintlessPirServerPublicParams& pub) {
  GeneratorConfig config;
  config.set_config_id(ConfigurationId(params, pub));
  *config.mutable_ciphertext_pad_seeds() = pub.prng_seed_linpir_ct_pads();
  config.set_galois_pad_seed(pub.prng_seed_linpir_gk_pad());
  return config;
}

absl::StatusOr<std::string> RandomId() {
  std::string bytes(32, '\0');
  if (RAND_bytes(reinterpret_cast<uint8_t*>(&bytes[0]), bytes.size()) != 1) {
    return absl::InternalError("Random generation failed.");
  }
  return bytes;
}

absl::StatusOr<std::string> DeriveSeed(
    const Preparation& prep, absl::string_view purpose, rlwe::PrngType type) {
  if (!IsId(prep.secret_seed()) || !IsId(prep.material_id()) ||
      !IsId(prep.config_id()) || purpose.empty()) {
    return absl::InvalidArgumentError("Invalid preparation or empty KDF domain.");
  }
  int size;
  if (type == rlwe::PRNG_TYPE_HKDF) size = rlwe::SingleThreadHkdfPrng::SeedLength();
  else if (type == rlwe::PRNG_TYPE_CHACHA) size = rlwe::SingleThreadChaChaPrng::SeedLength();
  else return absl::InvalidArgumentError("Unsupported PRNG.");
  std::string info;
  Append(info, "hintless/local-material/v1");
  Append(info, prep.material_id());
  Append(info, purpose);
  std::string result(size, '\0');
  if (HKDF(reinterpret_cast<uint8_t*>(&result[0]), result.size(), EVP_sha256(),
           reinterpret_cast<const uint8_t*>(prep.secret_seed().data()), 32,
           reinterpret_cast<const uint8_t*>(prep.config_id().data()), 32,
           reinterpret_cast<const uint8_t*>(info.data()), info.size()) != 1) {
    Wipe(result);
    return absl::InternalError("HKDF failed.");
  }
  return result;
}

absl::StatusOr<Material> LocalMaterialGenerator::Generate(const Preparation& prep) const {
  RLWE_RETURN_IF_ERROR(ValidateParameters(params_));
  if (!IsId(config_.config_id()) || prep.config_id() != config_.config_id() ||
      config_.ciphertext_pad_seeds_size() != params_.linpir_params.ts.size()) {
    return absl::InvalidArgumentError("Material configuration mismatch.");
  }
  Seed lwe_seed, rlwe_seed;
  RLWE_ASSIGN_OR_RETURN(lwe_seed.value, DeriveSeed(prep, "LWE-secret", params_.prng_type));
  RLWE_ASSIGN_OR_RETURN(rlwe_seed.value, DeriveSeed(prep, "RLWE-secret", params_.linpir_params.prng_type));
  RLWE_ASSIGN_OR_RETURN(auto prng, Prng(params_.prng_type, lwe_seed.value));
  RLWE_ASSIGN_OR_RETURN(auto key, lwe::SymmetricLweKey::Sample(params_.lwe_secret_dim, prng.get()));
  Material material;
  material.set_config_id(config_.config_id());
  material.set_material_id(prep.material_id());
  for (int k = 0; k < params_.linpir_params.ts.size(); ++k) {
    const auto& p = params_.linpir_params;
    RLWE_ASSIGN_OR_RETURN(auto context,
        Context::CreateForBfvFiniteFieldEncoding(p.log_n, p.qs, {}, p.ts[k]));
    RLWE_ASSIGN_OR_RETURN(auto client, LinClient::Create(
        p, &context, config_.ciphertext_pad_seeds(k), config_.galois_pad_seed()));
    const RI q = RI{1} << 32;
    std::vector<RI> encoded(key.Key().size());
    for (int i = 0; i < encoded.size(); ++i) {
      encoded[i] = hintless_simplepir::ConvertModulus<RI>(key.Key()[i], q, p.ts[k], q / 2);
    }
    // Upstream EncryptQuery and GenerateGaloisKey sample independent fresh
    // encryption/key-switch noise internally. They never use the LWE stream.
    RLWE_ASSIGN_OR_RETURN(auto ct, client->EncryptQuery(encoded, rlwe_seed.value));
    RLWE_ASSIGN_OR_RETURN(auto b, ct.Component(0));
    RLWE_ASSIGN_OR_RETURN(*material.add_ciphertexts(), b.Serialize(context.MainPrimeModuli()));
    if (k == 0) {
      RLWE_ASSIGN_OR_RETURN(auto gk, client->GenerateGaloisKey(rlwe_seed.value));
      for (const auto& part : gk.GetKeyB()) {
        RLWE_ASSIGN_OR_RETURN(*material.add_galois_key(), part.Serialize(context.MainPrimeModuli()));
      }
    }
  }
  // The library owns additional key/PRNG copies. Destruction is NOT a claim
  // of reliable secure erasure; audit/replace those allocators for a real TEE.
  return material;
}

Receipt MakeReceipt(const Material& material) {
  Receipt receipt;
  receipt.set_config_id(material.config_id());
  receipt.set_material_id(material.material_id());
  receipt.set_material_digest(Digest(material.SerializeAsString()));
  receipt.set_backend(kBackend);
  return receipt;
}

absl::StatusOr<std::unique_ptr<PreparedClient>> PreparedClient::Create(
    Parameters params, HintlessPirServerPublicParams pub) {
  RLWE_RETURN_IF_ERROR(ValidatePublic(params, pub));
  // Let the actual crypto implementation validate moduli/seeds/contexts now.
  RLWE_ASSIGN_OR_RETURN(auto check, hintless_simplepir::Client::Create(params, pub));
  return std::unique_ptr<PreparedClient>(new PreparedClient(std::move(params), std::move(pub)));
}
PreparedClient::~PreparedClient() {
  for (auto& item : entries_) Forget(item.second);
}
void PreparedClient::Forget(Entry& entry) {
  Wipe(entry.seed);
  entry.recovery.reset();
  ReleaseStorage(entry.request);
}

absl::StatusOr<Preparation> PreparedClient::BeginPreparation() {
  std::lock_guard<std::mutex> lock(mutex_);
  RLWE_ASSIGN_OR_RETURN(auto id, RandomId());
  if (entries_.count(id)) return absl::AlreadyExistsError("Material ID collision.");
  RLWE_ASSIGN_OR_RETURN(auto seed, RandomId());
  Preparation prep;
  prep.set_config_id(config_id_);
  prep.set_material_id(id);
  prep.set_secret_seed(seed);
  entries_[id].seed = std::move(seed);
  return prep;
}

absl::Status PreparedClient::AcceptReady(const Receipt& generated, const Receipt& installed) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = entries_.find(generated.material_id());
  if (it == entries_.end() || it->second.state != State::kPending) {
    return absl::FailedPreconditionError("No pending material for receipt.");
  }
  auto& entry = it->second;
  if (generated.config_id() != config_id_ || generated.backend() != kBackend ||
      !IsId(generated.material_digest()) ||
      generated.SerializeAsString() != installed.SerializeAsString()) {
    entry.state = State::kInvalid;
    Forget(entry);
    return absl::InvalidArgumentError("Generation and installation receipts do not match.");
  }
  entry.state = State::kReady;
  return absl::OkStatus();
}

absl::StatusOr<Query> PreparedClient::GenerateQuery(absl::string_view material_id, int64_t index) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = entries_.find(std::string(material_id));
  if (it == entries_.end() || it->second.state != State::kReady) {
    return absl::FailedPreconditionError("Material is not ready or already consumed.");
  }
  if (index < 0 || index >= params_.db_rows * params_.db_cols) {
    return absl::InvalidArgumentError("Index out of range.");
  }
  auto& entry = it->second;
  entry.state = State::kReserved;
  auto generate = [&]() -> absl::StatusOr<Query> {
    Preparation prep;
    prep.set_config_id(config_id_);
    prep.set_material_id(std::string(material_id));
    prep.set_secret_seed(entry.seed);
    Seed lwe_seed, rlwe_seed;
    RLWE_ASSIGN_OR_RETURN(lwe_seed.value, DeriveSeed(prep, "LWE-secret", params_.prng_type));
    RLWE_ASSIGN_OR_RETURN(rlwe_seed.value, DeriveSeed(prep, "RLWE-secret", params_.linpir_params.prng_type));
    Wipe(*prep.mutable_secret_seed());
    RLWE_ASSIGN_OR_RETURN(entry.recovery, hintless_simplepir::Client::CreateForPreparedMaterial(
        params_, public_params_, SessionId(material_id), rlwe_seed.value));
    RLWE_ASSIGN_OR_RETURN(auto low, entry.recovery->GeneratePreparedRequest(index, lwe_seed.value));
    RLWE_ASSIGN_OR_RETURN(auto request_id, RandomId());
    Query query;
    query.set_config_id(config_id_);
    query.set_material_id(std::string(material_id));
    query.set_request_id(request_id);
    *query.mutable_lwe_query() = low.ct_query_vector();
    return query;
  };
  auto result = generate();
  if (!result.ok()) {
    entry.state = State::kInvalid;
    Forget(entry);
    return result.status();
  }
  entry.request = *result;
  entry.state = State::kInFlight;
  Wipe(entry.seed);
  return result;
}

absl::StatusOr<Query> PreparedClient::Retry(absl::string_view material_id) const {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = entries_.find(std::string(material_id));
  if (it == entries_.end() || it->second.state != State::kInFlight) {
    return absl::FailedPreconditionError("No exact in-flight request to retry.");
  }
  return it->second.request;
}

absl::StatusOr<std::string> PreparedClient::Recover(const Response& response) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = entries_.find(response.material_id());
  if (it == entries_.end() || it->second.state != State::kInFlight) {
    return absl::FailedPreconditionError("No matching in-flight material.");
  }
  auto& entry = it->second;
  if (response.config_id() != config_id_ || response.request_id() != entry.request.request_id() ||
      !response.has_pir_response()) {
    entry.state = State::kInvalid;
    Forget(entry);
    return absl::InvalidArgumentError("Response binding mismatch; material invalidated.");
  }
  auto shape = CheckResponse(response.pir_response(), params_);
  if (!shape.ok()) {
    entry.state = State::kInvalid;
    Forget(entry);
    return shape;
  }
  auto result = entry.recovery->RecoverRecord(response.pir_response());
  entry.state = result.ok() ? State::kDone : State::kInvalid;
  Forget(entry);
  return result;
}

absl::Status PreparedClient::Abandon(absl::string_view material_id) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = entries_.find(std::string(material_id));
  if (it == entries_.end()) return absl::NotFoundError("Unknown material.");
  if (it->second.state == State::kDone || it->second.state == State::kInvalid) {
    return absl::FailedPreconditionError("Material is already terminal.");
  }
  it->second.state = State::kInvalid;
  Forget(it->second);
  return absl::OkStatus();
}

absl::StatusOr<State> PreparedClient::GetState(absl::string_view material_id) const {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = entries_.find(std::string(material_id));
  if (it == entries_.end()) return absl::NotFoundError("Unknown material.");
  return it->second.state;
}

absl::StatusOr<std::unique_ptr<PreparedServer>> PreparedServer::Create(Parameters params) {
  RLWE_RETURN_IF_ERROR(ValidateParameters(params));
  RLWE_ASSIGN_OR_RETURN(auto core, hintless_simplepir::Server::CreateWithRandomDatabaseRecords(params));
  auto server = std::unique_ptr<PreparedServer>(new PreparedServer(params, std::move(core)));
  RLWE_RETURN_IF_ERROR(server->Refresh());
  return server;
}

HintlessPirServerPublicParams PreparedServer::PublicParams() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return core_->GetPublicParams();
}

absl::Status PreparedServer::Refresh() {
  std::lock_guard<std::mutex> lock(mutex_);
  entries_.clear();
  config_id_.clear();
  RLWE_RETURN_IF_ERROR(core_->Preprocess());
  config_id_ = ConfigurationId(params_, core_->GetPublicParams());
  return absl::OkStatus();
}

absl::StatusOr<Receipt> PreparedServer::Install(const Material& material) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!IsId(material.material_id()) || material.config_id() != config_id_ ||
      !IsId(config_id_) || material.ciphertexts_size() != params_.linpir_params.ts.size() ||
      material.galois_key_size() == 0) {
    return absl::InvalidArgumentError("Invalid material or stale configuration.");
  }
  if (entries_.count(material.material_id())) return absl::AlreadyExistsError("Material ID already installed or consumed.");
  for (const auto& ct : material.ciphertexts()) {
    RLWE_RETURN_IF_ERROR(CheckPolynomial(ct, params_));
  }
  for (const auto& key : material.galois_key()) {
    RLWE_RETURN_IF_ERROR(CheckPolynomial(key, params_));
  }
  // Tombstone first: an installation failure never makes the ID reusable.
  auto& entry = entries_[material.material_id()];
  entry.state = State::kInvalid;
  const auto pub = core_->GetPublicParams();
  HintlessPirSessionInitRequest init;
  init.set_client_id(SessionId(material.material_id()));
  init.set_database_version(pub.database_version());
  init.set_pool_epoch(pub.pool_epoch());
  *init.mutable_linpir_gk_bs() = material.galois_key();
  RLWE_ASSIGN_OR_RETURN(auto ack, core_->InitializeSession(init));
  entry.material = material;
  entry.state = State::kReady;
  return MakeReceipt(material);
}

absl::StatusOr<Response> PreparedServer::Handle(const Query& query) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (query.config_id() != config_id_ || !IsId(query.material_id()) ||
      !IsId(query.request_id()) || !query.has_lwe_query() ||
      query.lwe_query().b_coeffs_size() != params_.db_cols) {
    return absl::InvalidArgumentError("Invalid query or stale configuration.");
  }
  auto it = entries_.find(query.material_id());
  if (it == entries_.end()) return absl::NotFoundError("Material not installed.");
  auto& entry = it->second;
  const std::string bytes = query.SerializeAsString();
  if (entry.state == State::kDone && entry.request_bytes == bytes && entry.response.has_pir_response()) {
    return entry.response;  // Exact retry: no second evaluation or new query.
  }
  if (entry.state != State::kReady) return absl::AlreadyExistsError("Material consumed; only exact cached retries are allowed.");
  entry.state = State::kInFlight;
  entry.request_bytes = bytes;
  const auto pub = core_->GetPublicParams();
  HintlessPirRequest low;
  low.set_client_id(SessionId(query.material_id()));
  low.set_database_version(pub.database_version());
  low.set_pool_epoch(pub.pool_epoch());
  low.set_query_token(1);
  *low.mutable_ct_query_vector() = query.lwe_query();
  *low.mutable_linpir_ct_bs() = entry.material.ciphertexts();
  auto result = core_->HandleRequest(low);
  core_->RemoveSession(SessionId(query.material_id()));
  ReleaseStorage(entry.material);
  if (!result.ok()) {
    entry.state = State::kInvalid;
    return result.status();
  }
  Response response;
  response.set_config_id(config_id_);
  response.set_material_id(query.material_id());
  response.set_request_id(query.request_id());
  *response.mutable_pir_response() = std::move(*result);
  entry.response = response;
  entry.state = State::kDone;
  return response;
}

absl::Status PreparedServer::Release(absl::string_view material_id) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = entries_.find(std::string(material_id));
  if (it == entries_.end()) return absl::NotFoundError("Unknown material.");
  core_->RemoveSession(SessionId(material_id));
  ReleaseStorage(it->second.material);
  ReleaseStorage(it->second.response);
  std::string().swap(it->second.request_bytes);
  it->second.state = State::kInvalid;
  return absl::OkStatus();
}

absl::StatusOr<std::string> PreparedServer::ExpectedRecord(int64_t index) const {
  std::lock_guard<std::mutex> lock(mutex_);
  return core_->GetDatabase()->Record(index);
}

Parameters DemoParameters() {
  return Parameters{
    .db_rows = 8, .db_cols = 8, .db_record_bit_size = 64,
    .lwe_secret_dim = 32, .lwe_modulus_bit_size = 32,
    .lwe_plaintext_bit_size = 8, .lwe_error_variance = 8,
    .linpir_params = linpir::RlweParameters<RI>{
      .log_n = 12, .qs = {35184371884033ULL, 35184371703809ULL},
      .ts = {2056193, 1990657}, .gadget_log_bs = {16, 16},
      .error_variance = 8, .prng_type = rlwe::PRNG_TYPE_HKDF,
      .rows_per_block = 8},
    .prng_type = rlwe::PRNG_TYPE_HKDF, .session_pool_capacity = 1};
}

absl::StatusOr<Parameters> ParametersForProfile(absl::string_view profile) {
  auto params = DemoParameters();
  if (profile == "functional") return params;
  int database_side = 0;
  if (profile == "8mb") database_side = 1024;
  else if (profile == "512mb") database_side = 8192;
  else if (profile == "2gb") database_side = 16384;
  else if (profile == "8gb") database_side = 32768;
  else return absl::InvalidArgumentError("Profile must be functional, 8mb, 512mb, 2gb, or 8gb.");
  params.db_rows = database_side;
  params.db_cols = database_side;
  params.lwe_secret_dim = 1024;
  params.linpir_params.rows_per_block = 1024;
  // Two 8192-NTT-friendly primes keep the manuscript's two-branch layout
  // while satisfying the deterministic balanced reconstruction condition
  // product(ts) > n * 2^32. This is a correctness profile, not a concrete
  // LWE/RLWE security estimate.
  params.linpir_params.ts = {2236417, 2277377};
  RLWE_RETURN_IF_ERROR(ValidateParameters(params));
  return params;
}
}  // namespace hintless_pir::local_material
