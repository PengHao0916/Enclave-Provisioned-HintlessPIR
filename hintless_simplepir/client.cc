// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "hintless_simplepir/client.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "Eigen/Core"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "hintless_simplepir/parameters.h"
#include "hintless_simplepir/serialization.pb.h"
#include "hintless_simplepir/utils.h"
#include "lwe/encode.h"
#include "lwe/lwe_symmetric_encryption.h"
#include "lwe/types.h"
#include "shell_encryption/int256.h"
#include "shell_encryption/prng/prng.h"
#include "shell_encryption/prng/single_thread_chacha_prng.h"
#include "shell_encryption/prng/single_thread_hkdf_prng.h"
#include "shell_encryption/rns/crt_interpolation.h"
#include "shell_encryption/status_macros.h"

namespace hintless_pir {
namespace hintless_simplepir {

absl::StatusOr<std::unique_ptr<Client>> Client::Create(
    const Parameters& params,
    const HintlessPirServerPublicParams& public_params) {
  if (!(params.prng_type == rlwe::PRNG_TYPE_HKDF ||
        params.prng_type == rlwe::PRNG_TYPE_CHACHA)) {
    return absl::InvalidArgumentError("Invalid PRNG type in `params`.");
  }
  // Create LinPir clients, one per plaintext modulus in `ts`.
  auto const& rlwe_params = params.linpir_params;
  int num_linpir_instances = rlwe_params.ts.size();
  if (!public_params.has_pool_capacity() || public_params.pool_capacity() == 0 ||
      public_params.pool_capacity() != params.session_pool_capacity) {
    return absl::InvalidArgumentError(
        "`public_params` contains an invalid pool capacity.");
  }
  int expected_pool_entries =
      public_params.pool_capacity() * num_linpir_instances;
  if (public_params.prng_seed_linpir_ct_pads_size() != expected_pool_entries ||
      public_params.linpir_response_hints_size() != expected_pool_entries) {
    return absl::InvalidArgumentError(
        "`public_params` contains an incorrect one-time pad pool.");
  }
  if (!public_params.has_database_version() ||
      !public_params.has_pool_epoch()) {
    return absl::InvalidArgumentError(
        "`public_params` is missing versioned pool metadata.");
  }
  std::vector<std::unique_ptr<const RlweRnsContext>> rlwe_contexts;
  std::vector<std::unique_ptr<LinPirClient>> linpir_clients;
  rlwe_contexts.reserve(num_linpir_instances);
  linpir_clients.reserve(num_linpir_instances);
  for (int i = 0; i < num_linpir_instances; ++i) {
    RLWE_ASSIGN_OR_RETURN(
        auto rlwe_context,
        RlweRnsContext::CreateForBfvFiniteFieldEncoding(
            rlwe_params.log_n, rlwe_params.qs, /*ps=*/{}, rlwe_params.ts[i]));
    auto rlwe_context_ptr =
        std::make_unique<const RlweRnsContext>(std::move(rlwe_context));
    RLWE_ASSIGN_OR_RETURN(
        auto linpir_client,
        LinPirClient::Create(rlwe_params, rlwe_context_ptr.get(),
                             public_params.prng_seed_linpir_ct_pads(i),
                             public_params.prng_seed_linpir_gk_pad()));
    rlwe_contexts.push_back(std::move(rlwe_context_ptr));
    linpir_clients.push_back(std::move(linpir_client));
  }
  std::vector<const RlwePrimeModulus*> rlwe_moduli =
      rlwe_contexts[0]->MainPrimeModuli();

  // Create another RNS context for computing CRT interpolation wrt plaintext
  // moduli. We set its plaintext modulus to 2 as a place holder.
  RLWE_ASSIGN_OR_RETURN(
      RlweRnsContext crt_context,
      RlweRnsContext::Create(rlwe_params.log_n, rlwe_params.ts, /*ps=*/{}, 2));

  auto client = absl::WrapUnique(new Client(
      params, public_params, std::move(rlwe_contexts), std::move(rlwe_moduli),
      std::move(linpir_clients), std::move(crt_context)));

  if (params.prng_type == rlwe::PRNG_TYPE_HKDF) {
    RLWE_ASSIGN_OR_RETURN(client->client_id_,
                          rlwe::SingleThreadHkdfPrng::GenerateSeed());
    RLWE_ASSIGN_OR_RETURN(client->session_linpir_sk_seed_,
                          rlwe::SingleThreadHkdfPrng::GenerateSeed());
  } else {
    RLWE_ASSIGN_OR_RETURN(client->client_id_,
                          rlwe::SingleThreadChaChaPrng::GenerateSeed());
    RLWE_ASSIGN_OR_RETURN(client->session_linpir_sk_seed_,
                          rlwe::SingleThreadChaChaPrng::GenerateSeed());
  }
  return client;
}

absl::StatusOr<HintlessPirSessionInitRequest>
Client::GenerateSessionInitRequest() {
  std::lock_guard<std::mutex> lock(request_mutex_);
  if (prepared_material_mode_) {
    return absl::FailedPreconditionError("Prepared materials have no client key upload.");
  }
  if (session_init_generated_) {
    return cached_session_init_request_;
  }
  if (linpir_clients_.empty()) {
    return absl::FailedPreconditionError("No LinPir client available.");
  }
  HintlessPirSessionInitRequest request;
  request.set_client_id(client_id_);
  request.set_database_version(database_version_);
  request.set_pool_epoch(pool_epoch_);
  RLWE_ASSIGN_OR_RETURN(
      auto gk,
      linpir_clients_[0]->GenerateGaloisKey(session_linpir_sk_seed_));
  for (const auto& gk_b : gk.GetKeyB()) {
    RLWE_ASSIGN_OR_RETURN(*request.add_linpir_gk_bs(),
                          gk_b.Serialize(rlwe_moduli_));
  }
  cached_session_init_request_ = request;
  session_init_generated_ = true;
  return cached_session_init_request_;
}

absl::Status Client::AcceptSessionInitResponse(
    const HintlessPirSessionInitResponse& response) {
  std::lock_guard<std::mutex> lock(request_mutex_);
  if (!session_init_generated_) {
    return absl::FailedPreconditionError(
        "Generate the session initialization request first.");
  }
  if (!response.has_client_id() || response.client_id() != client_id_ ||
      !response.has_database_version() ||
      response.database_version() != database_version_ ||
      !response.has_pool_epoch() || response.pool_epoch() != pool_epoch_ ||
      !response.has_pool_capacity() ||
      response.pool_capacity() != pool_capacity_) {
    return absl::InvalidArgumentError(
        "Session acknowledgement does not match the requested session.");
  }
  session_ready_ = true;
  return absl::OkStatus();
}

absl::Status Client::AbandonOutstandingRequest() {
  std::lock_guard<std::mutex> lock(request_mutex_);
  if (!has_outstanding_request_) {
    return absl::FailedPreconditionError("There is no outstanding request.");
  }
  has_outstanding_request_ = false;
  return absl::OkStatus();
}

absl::StatusOr<HintlessPirRequest> Client::GenerateRequest(int64_t index) {
  if (prepared_material_mode_) {
    return absl::FailedPreconditionError("Use GeneratePreparedRequest for this client.");
  }
  return GenerateRequestInternal(index, {});
}

absl::StatusOr<std::unique_ptr<Client>> Client::CreateForPreparedMaterial(
    const Parameters& params, const HintlessPirServerPublicParams& public_params,
    absl::string_view material_id, absl::string_view rlwe_secret_seed) {
  if (params.session_pool_capacity != 1 || material_id.empty()) {
    return absl::InvalidArgumentError("Prepared mode requires one static pad and an ID.");
  }
  RLWE_ASSIGN_OR_RETURN(auto client, Create(params, public_params));
  client->client_id_ = std::string(material_id);
  client->session_linpir_sk_seed_ = std::string(rlwe_secret_seed);
  client->prepared_material_mode_ = true;
  client->session_ready_ = true;
  return client;
}

absl::StatusOr<HintlessPirRequest> Client::GeneratePreparedRequest(
    int64_t index, absl::string_view lwe_secret_seed) {
  if (!prepared_material_mode_ || lwe_secret_seed.empty()) {
    return absl::FailedPreconditionError("A prepared key and LWE seed are required.");
  }
  return GenerateRequestInternal(index, lwe_secret_seed);
}

absl::StatusOr<HintlessPirRequest> Client::GenerateRequestInternal(
    int64_t index, absl::string_view lwe_secret_seed) {
  std::lock_guard<std::mutex> lock(request_mutex_);
  if (!session_ready_) {
    return absl::FailedPreconditionError(
        "The server has not acknowledged session initialization.");
  }
  if (index < 0 || index >= params_.db_rows * params_.db_cols) {
    return absl::InvalidArgumentError("`index` out of range.");
  }
  if (has_outstanding_request_) {
    return absl::FailedPreconditionError(
        "A request is already outstanding; recover it or burn its token.");
  }
  if (next_query_token_ > pool_capacity_) {
    return absl::ResourceExhaustedError(
        "The one-time public-component pool is exhausted.");
  }
  // Consume before sampling or transmission. All error paths burn this token.
  const uint64_t query_token = next_query_token_++;

  // Step 1. Encrypting the selection vector under LWE.
  lwe::Matrix lwe_pad;
  std::unique_ptr<rlwe::SecurePrng> lwe_enc_prng;
  if (params_.prng_type == rlwe::PRNG_TYPE_HKDF) {
    RLWE_ASSIGN_OR_RETURN(auto pad_prng, rlwe::SingleThreadHkdfPrng::Create(
                                             prng_seed_lwe_query_pad_));
    RLWE_ASSIGN_OR_RETURN(
        lwe_pad, lwe::ExpandPad(params_.db_cols, params_.lwe_secret_dim,
                                pad_prng.get()));
    RLWE_ASSIGN_OR_RETURN(std::string prng_seed_enc,
                          rlwe::SingleThreadHkdfPrng::GenerateSeed());
    RLWE_ASSIGN_OR_RETURN(lwe_enc_prng,
                          rlwe::SingleThreadHkdfPrng::Create(prng_seed_enc));

  } else {
    RLWE_ASSIGN_OR_RETURN(auto pad_prng, rlwe::SingleThreadChaChaPrng::Create(
                                             prng_seed_lwe_query_pad_));
    RLWE_ASSIGN_OR_RETURN(
        lwe_pad, lwe::ExpandPad(params_.db_cols, params_.lwe_secret_dim,
                                pad_prng.get()));
    RLWE_ASSIGN_OR_RETURN(std::string prng_seed_enc,
                          rlwe::SingleThreadChaChaPrng::GenerateSeed());
    RLWE_ASSIGN_OR_RETURN(lwe_enc_prng,
                          rlwe::SingleThreadChaChaPrng::Create(prng_seed_enc));
  }
  std::unique_ptr<rlwe::SecurePrng> secret_prng;
  if (prepared_material_mode_) {
    if (params_.prng_type == rlwe::PRNG_TYPE_HKDF) {
      RLWE_ASSIGN_OR_RETURN(secret_prng,
          rlwe::SingleThreadHkdfPrng::Create(lwe_secret_seed));
    } else {
      RLWE_ASSIGN_OR_RETURN(secret_prng,
          rlwe::SingleThreadChaChaPrng::Create(lwe_secret_seed));
    }
  }
  RLWE_ASSIGN_OR_RETURN(lwe::SymmetricLweKey lwe_secret_key,
      lwe::SymmetricLweKey::Sample(params_.lwe_secret_dim,
          prepared_material_mode_ ? secret_prng.get() : lwe_enc_prng.get()));

  // Choosing the largest scaling factor that supports our plaintext space
  int log_scaling_factor =
      params_.lwe_modulus_bit_size - params_.lwe_plaintext_bit_size;

  // Plaintext is a selection vector for col_idx
  int64_t row_idx = index / params_.db_cols;
  int64_t col_idx = index % params_.db_cols;
  lwe::Vector query_vector = lwe::Vector::Zero(params_.db_cols);
  query_vector[col_idx] = 1;

  RLWE_RETURN_IF_ERROR(lwe_secret_key.EncryptFromPadInPlace(
      query_vector, lwe_pad, log_scaling_factor, lwe_enc_prng.get()));

  // Cache the per request state.
  state_ = ClientState{.row_idx = row_idx,
                       .col_idx = col_idx,
                       .query_token = query_token};

  HintlessPirRequest request;
  *request.mutable_ct_query_vector() = SerializeLweCiphertext(query_vector);
  request.set_client_id(client_id_);
  request.set_database_version(database_version_);
  request.set_pool_epoch(pool_epoch_);
  request.set_query_token(query_token);

  if (prepared_material_mode_) {
    // Encryption and full Galois-key generation already occurred at the
    // material generator. The client only restores decryption keys here.
    for (const auto& linpir_client : linpir_clients_) {
      RLWE_RETURN_IF_ERROR(linpir_client->RestoreSecretKey(session_linpir_sk_seed_));
    }
  } else {
    RLWE_RETURN_IF_ERROR(
        GenerateLinPirRequestInPlace(request, lwe_secret_key.Key(), query_token));
  }
  has_outstanding_request_ = true;
  return request;
}

absl::Status Client::GenerateLinPirRequestInPlace(
    HintlessPirRequest& request, const lwe::Vector& lwe_secret,
    uint64_t query_token) const {
  if (linpir_clients_.empty()) {
    return absl::InvalidArgumentError("No LinPir client available.");
  }

  if (query_token == 0 || query_token > pool_capacity_) {
    return absl::InvalidArgumentError("Query token is outside the pad pool.");
  }

  RlweInteger lwe_modulus = RlweInteger{1} << params_.lwe_modulus_bit_size;
  for (size_t k = 0; k < linpir_clients_.size(); ++k) {
    RlweInteger plaintext_modulus = rlwe_contexts_[k]->PlaintextModulus();
    std::vector<RlweInteger> lwe_secret_mod_t =
        EncodeLweVector(lwe_secret, lwe_modulus, plaintext_modulus);
    RLWE_ASSIGN_OR_RETURN(
        auto ct, linpir_clients_[k]->EncryptQuery(lwe_secret_mod_t,
            session_linpir_sk_seed_,
            linpir_ct_pad_seeds_[(query_token - 1) *
                                     linpir_clients_.size() +
                                 k]));
    RLWE_ASSIGN_OR_RETURN(auto ct_b, ct.Component(0));
    RLWE_ASSIGN_OR_RETURN(*request.add_linpir_ct_bs(),
                          ct_b.Serialize(rlwe_moduli_));
  }

  return absl::OkStatus();
}

std::vector<Client::RlweInteger> Client::EncodeLweVector(
    const lwe::Vector& lwe_vector, RlweInteger lwe_modulus,
    RlweInteger encode_modulus) {
  RlweInteger lwe_modulus_half = lwe_modulus >> 1;
  std::vector<RlweInteger> lwe_vector_mod_t(lwe_vector.size(), 0);
  for (int i = 0; i < lwe_vector.size(); ++i) {
    RlweInteger x = lwe_vector[i];
    lwe_vector_mod_t[i] =
        ConvertModulus(x, lwe_modulus, encode_modulus, lwe_modulus_half);
  }
  return lwe_vector_mod_t;
}

absl::StatusOr<std::string> Client::RecoverRecord(
    const HintlessPirResponse& response) {
  std::lock_guard<std::mutex> lock(request_mutex_);
  if (!has_outstanding_request_) {
    return absl::FailedPreconditionError(
        "There is no outstanding request to recover.");
  }
  if (!response.has_client_id() || response.client_id() != client_id_ ||
      !response.has_database_version() ||
      response.database_version() != database_version_ ||
      !response.has_pool_epoch() || response.pool_epoch() != pool_epoch_ ||
      !response.has_query_token() ||
      response.query_token() != state_.query_token) {
    return absl::InvalidArgumentError(
        "`response` does not match the outstanding session query.");
  }
  int num_shards =
      DivAndRoundUp(params_.db_record_bit_size, params_.lwe_plaintext_bit_size);
  if (response.ct_records_size() != num_shards) {
    return absl::InvalidArgumentError("`response` has incorrect size.");
  }

  // Recover decryption_parts = Hint * LWE secret = Database * A * LWE secret.
  RLWE_ASSIGN_OR_RETURN(std::vector<lwe::Vector> decryption_parts,
                        RecoverLweDecryptionParts(response,
                                                  state_.query_token));

  // Decrypt the LWE ciphertexts in response.
  std::vector<lwe::Integer> values;
  values.reserve(response.ct_records_size());
  for (int i = 0; i < response.ct_records_size(); ++i) {
    std::vector<lwe::Integer> ct_records =
        DeserializeLweCiphertext(response.ct_records(i));
    if (ct_records.size() != params_.db_rows) {
      return absl::InvalidArgumentError(absl::StrCat(
          "The server response has incorrect dimension; got ",
          ct_records.size(), " but expecting ", params_.db_rows, "."));
    }

    // Remove hint * s from the server response, which gives us \Delta * m + e.
    lwe::Vector noisy_plaintext{{ct_records[state_.row_idx]}};
    noisy_plaintext[0] -= decryption_parts[i][state_.row_idx];

    // Remove the error e.
    int log_scaling_factor =
        params_.lwe_modulus_bit_size - params_.lwe_plaintext_bit_size;
    RLWE_RETURN_IF_ERROR(
        lwe::RemoveErrorInPlace(noisy_plaintext, log_scaling_factor));

    // Extracting the coefficient from the 1 x 1 matrix noisy_plaintext.
    values.push_back(noisy_plaintext.eval()(0));
  }

  std::string record = ReconstructRecord(values, params_);
  has_outstanding_request_ = false;
  return record;
}

absl::StatusOr<std::vector<lwe::Vector>> Client::RecoverLweDecryptionParts(
    const HintlessPirResponse& response, uint64_t query_token) const {
  using BigInteger = rlwe::uint256;

  if (query_token == 0 || query_token > pool_capacity_) {
    return absl::InvalidArgumentError("Query token is outside the pad pool.");
  }

  auto plaintext_moduli = crt_context_.MainPrimeModuli();
  int num_linpir_plaintext_moduli = plaintext_moduli.size();
  if (response.linpir_responses_size() != num_linpir_plaintext_moduli) {
    return absl::InvalidArgumentError(
        "`response` contains unexpected number of LinPir responses.");
  }

  int num_shards =
      DivAndRoundUp(params_.db_record_bit_size, params_.lwe_plaintext_bit_size);
  if (num_shards != response.linpir_responses(0).ct_inner_products_size()) {
    return absl::InvalidArgumentError(
        "`response` contains an expected number of shards.");
  }

  // CRT decomposed values of Hint * LWE secrets, where the first dimension
  // is per database shard, then per CRT modulus, and then per block in the
  // shard.
  std::vector<std::vector<std::vector<RlweModularInt>>> hint_crt_values(
      num_shards);
  for (auto& h : hint_crt_values) {
    h.resize(num_linpir_plaintext_moduli);
  }
  for (int k = 0; k < num_linpir_plaintext_moduli; ++k) {
    size_t response_pad_index =
        (query_token - 1) * num_linpir_plaintext_moduli + k;
    RLWE_ASSIGN_OR_RETURN(
        auto hint_values_mod_tk,
        linpir_clients_[k]->Recover(response.linpir_responses(k),
                                   linpir_response_pads_[response_pad_index]));
    auto mod_params_tk = plaintext_moduli[k]->ModParams();
    for (int i = 0; i < num_shards; ++i) {
      hint_crt_values[i][k].reserve(hint_values_mod_tk[i].size());
      for (auto const& hint_value : hint_values_mod_tk[i]) {
        RLWE_ASSIGN_OR_RETURN(auto hint_mod_tk, RlweModularInt::ImportInt(
                                                    hint_value, mod_params_tk));
        hint_crt_values[i][k].push_back(std::move(hint_mod_tk));
      }
    }
  }

  // CRT interpolates to get Hint * LWE secrets as balanced mod-t values, where
  // t is the product of plaintext moduli. Then convert them wrt LWE modulus.
  BigInteger p = 1;
  for (auto pi : plaintext_moduli) {
    p *= rlwe::ConvertToBigInteger<RlweInteger, BigInteger>(pi->Modulus());
  }
  BigInteger p_half = p / 2;
  BigInteger lwe_modulus = BigInteger(1) << params_.lwe_modulus_bit_size;
  std::vector<BigInteger> p_hats =
      rlwe::RnsModulusComplements<RlweModularInt, BigInteger>(plaintext_moduli);
  RLWE_ASSIGN_OR_RETURN(
      std::vector<RlweModularInt> p_hat_invs,
      crt_context_.MainPrimeModulusCrtFactors(num_linpir_plaintext_moduli - 1));

  std::vector<lwe::Vector> hint_vectors;
  hint_vectors.reserve(num_shards);
  for (int j = 0; j < num_shards; ++j) {
    RLWE_ASSIGN_OR_RETURN(
        std::vector<BigInteger> hint_values,
        (rlwe::CrtInterpolation<RlweModularInt, BigInteger>(
            hint_crt_values[j], plaintext_moduli, p_hats, p_hat_invs)));

    lwe::Vector hint = lwe::Vector::Zero(hint_values.size());
    for (int i = 0; i < hint_values.size(); ++i) {
      BigInteger x = hint_values[i] % p;
      hint[i] =
          static_cast<RlweInteger>(ConvertModulus(x, p, lwe_modulus, p_half));
    }
    hint_vectors.push_back(std::move(hint));
  }

  return hint_vectors;
}

}  // namespace hintless_simplepir
}  // namespace hintless_pir
