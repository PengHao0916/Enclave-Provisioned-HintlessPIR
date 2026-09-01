/*
 * Copyright 2024 Google LLC.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "linpir/server.h"

#include <cmath>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "google/protobuf/repeated_ptr_field.h"
#include "linpir/database.h"
#include "linpir/parameters.h"
#include "shell_encryption/prng/prng.h"
#include "shell_encryption/prng/single_thread_chacha_prng.h"
#include "shell_encryption/prng/single_thread_hkdf_prng.h"
#include "shell_encryption/status_macros.h"

namespace hintless_pir {
namespace linpir {

template <typename RlweInteger>
absl::StatusOr<std::unique_ptr<Server<RlweInteger>>>
Server<RlweInteger>::Create(
    const RlweParameters<RlweInteger>& parameters,
    const RnsContext* rns_context,
    const std::vector<Database<RlweInteger>*>& databases,
    absl::string_view prng_seed_ct_pad, absl::string_view prng_seed_gk_pad) {
  return Server<RlweInteger>::Create(
      parameters, rns_context, databases,
      std::vector<std::string>{std::string(prng_seed_ct_pad)},
      prng_seed_gk_pad);
}

template <typename RlweInteger>
absl::StatusOr<std::unique_ptr<Server<RlweInteger>>>
Server<RlweInteger>::Create(
    const RlweParameters<RlweInteger>& parameters,
    const RnsContext* rns_context,
    const std::vector<Database<RlweInteger>*>& databases,
    const std::vector<std::string>& prng_seed_ct_pads,
    absl::string_view prng_seed_gk_pad) {
  if (!(parameters.prng_type == rlwe::PRNG_TYPE_HKDF ||
        parameters.prng_type == rlwe::PRNG_TYPE_CHACHA)) {
    return absl::InvalidArgumentError("Invalid `prng_type`.");
  }
  if (rns_context == nullptr) {
    return absl::InvalidArgumentError("`rns_context` must not be null.");
  }
  if (prng_seed_ct_pads.empty()) {
    return absl::InvalidArgumentError(
        "`prng_seed_ct_pads` must contain at least one seed.");
  }

  auto rns_moduli = rns_context->MainPrimeModuli();
  int level = rns_moduli.size() - 1;
  RLWE_ASSIGN_OR_RETURN(auto q_hats,
                        rns_context->MainPrimeModulusComplements(level));
  RLWE_ASSIGN_OR_RETURN(auto q_hat_invs,
                        rns_context->MainPrimeModulusCrtFactors(level));
  RLWE_ASSIGN_OR_RETURN(
      RnsGadget rns_gadget,
      RnsGadget::Create(parameters.log_n, parameters.gadget_log_bs, q_hats,
                        q_hat_invs, rns_moduli));
  RLWE_ASSIGN_OR_RETURN(
      auto rns_error_params,
      RnsErrorParams::Create(
          parameters.log_n, rns_moduli, /*aux_moduli=*/{},
          std::log2(static_cast<double>(rns_context->PlaintextModulus())),
          std::sqrt(parameters.error_variance)));

  return absl::WrapUnique(new Server<RlweInteger>(
      parameters, prng_seed_ct_pads, std::string(prng_seed_gk_pad),
      rns_context, std::move(rns_moduli), std::move(rns_gadget),
      std::move(rns_error_params), databases));
}

template <typename RlweInteger>
absl::StatusOr<std::unique_ptr<Server<RlweInteger>>>
Server<RlweInteger>::Create(
    const RlweParameters<RlweInteger>& parameters,
    const RnsContext* rns_context,
    const std::vector<Database<RlweInteger>*>& databases) {
  // Sample PRNG seeds for the query vector and the Galois key.
  std::string prng_seed_ct_pad, prng_seed_gk_pad;
  if (parameters.prng_type == rlwe::PRNG_TYPE_HKDF) {
    RLWE_ASSIGN_OR_RETURN(prng_seed_ct_pad,
                          rlwe::SingleThreadHkdfPrng::GenerateSeed());
    RLWE_ASSIGN_OR_RETURN(prng_seed_gk_pad,
                          rlwe::SingleThreadHkdfPrng::GenerateSeed());
  } else if (parameters.prng_type == rlwe::PRNG_TYPE_CHACHA) {
    RLWE_ASSIGN_OR_RETURN(prng_seed_ct_pad,
                          rlwe::SingleThreadChaChaPrng::GenerateSeed());
    RLWE_ASSIGN_OR_RETURN(prng_seed_gk_pad,
                          rlwe::SingleThreadChaChaPrng::GenerateSeed());
  } else {
    return absl::InvalidArgumentError("Invalid `prng_type`.");
  }

  return Server<RlweInteger>::Create(parameters, rns_context, databases,
                                     prng_seed_ct_pad, prng_seed_gk_pad);
}

template <typename RlweInteger>
absl::Status Server<RlweInteger>::Preprocess() {
  query_pad_states_.clear();
  gk_pads_.clear();

  // The Galois-key pad is session invariant and shared by every pool entry.
  int log_n = rns_context_->LogN();
  int gadget_dim = rns_gadget_.Dimension();
  RLWE_ASSIGN_OR_RETURN(gk_pads_, RnsGaloisKey::SampleRandomPad(
                                      gadget_dim, log_n, rns_moduli_,
                                      prng_seed_gk_pad_, params_.prng_type));

  query_pad_states_.reserve(prng_seed_ct_pads_.size());
  for (const std::string& seed : prng_seed_ct_pads_) {
    std::unique_ptr<rlwe::SecurePrng> prng_ct;
    if (params_.prng_type == rlwe::PRNG_TYPE_HKDF) {
      RLWE_ASSIGN_OR_RETURN(prng_ct,
                            rlwe::SingleThreadHkdfPrng::Create(seed));
    } else {
      RLWE_ASSIGN_OR_RETURN(prng_ct,
                            rlwe::SingleThreadChaChaPrng::Create(seed));
    }

    QueryPadState pad_state;
    int num_rotations = params_.rows_per_block / 2;
    pad_state.ct_pads.reserve(num_rotations);
    pad_state.ct_sub_pad_digits.reserve(num_rotations - 1);

    RLWE_ASSIGN_OR_RETURN(auto ct_pad, RnsPolynomial::SampleUniform(
                                           log_n, prng_ct.get(), rns_moduli_));
    RLWE_RETURN_IF_ERROR(ct_pad.NegateInPlace(rns_moduli_));
    pad_state.ct_pads.push_back(std::move(ct_pad));

    for (int i = 1; i < num_rotations; ++i) {
      RLWE_ASSIGN_OR_RETURN(
          RnsPolynomial prev_sub_a,
          pad_state.ct_pads[i - 1].Substitute(5, rns_moduli_));
      if (prev_sub_a.IsNttForm()) {
        RLWE_RETURN_IF_ERROR(prev_sub_a.ConvertToCoeffForm(rns_moduli_));
      }
      RLWE_ASSIGN_OR_RETURN(auto prev_sub_a_digits,
                            rns_gadget_.Decompose(prev_sub_a, rns_moduli_));
      for (auto& digit : prev_sub_a_digits) {
        RLWE_RETURN_IF_ERROR(digit.ConvertToNttForm(rns_moduli_));
      }

      RLWE_ASSIGN_OR_RETURN(
          auto curr_a,
          RnsPolynomial::CreateZero(log_n, rns_moduli_, /*is_ntt=*/true));
      for (int j = 0; j < prev_sub_a_digits.size(); ++j) {
        RLWE_RETURN_IF_ERROR(curr_a.FusedMulAddInPlace(
            prev_sub_a_digits[j], gk_pads_[j], rns_moduli_));
      }
      pad_state.ct_pads.push_back(std::move(curr_a));
      pad_state.ct_sub_pad_digits.push_back(std::move(prev_sub_a_digits));
    }

    pad_state.response_pads.reserve(databases_.size());
    for (const auto* database : databases_) {
      RLWE_ASSIGN_OR_RETURN(
          auto response_pads,
          database->ComputePadInnerProducts(pad_state.ct_pads));
      pad_state.response_pads.push_back(std::move(response_pads));
    }
    query_pad_states_.push_back(std::move(pad_state));
  }
  return absl::OkStatus();
}

template <typename RlweInteger>
absl::StatusOr<const typename Server<RlweInteger>::QueryPadState*>
Server<RlweInteger>::PadStateForToken(uint64_t query_token) const {
  if (query_token == 0 || query_token > query_pad_states_.size()) {
    return absl::InvalidArgumentError("Query token is outside the pad pool.");
  }
  return &query_pad_states_[query_token - 1];
}

template <typename RlweInteger>
absl::Status Server<RlweInteger>::CacheGaloisKey(
    absl::string_view session_id,
    const google::protobuf::RepeatedPtrField<
        ::rlwe::SerializedRnsPolynomial>& proto_gk_key_bs) const {
  if (session_id.empty()) {
    return absl::InvalidArgumentError("Session ID must not be empty.");
  }
  if (proto_gk_key_bs.empty()) {
    return absl::InvalidArgumentError("Galois key must not be empty.");
  }
  std::vector<RnsPolynomial> gk_key_bs;
  gk_key_bs.reserve(proto_gk_key_bs.size());
  for (const auto& proto_poly : proto_gk_key_bs) {
    RLWE_ASSIGN_OR_RETURN(
        RnsPolynomial gk_key_b,
        RnsPolynomial::Deserialize(proto_poly, rns_moduli_));
    gk_key_bs.push_back(std::move(gk_key_b));
  }
  RLWE_ASSIGN_OR_RETURN(
      RnsGaloisKey gk,
      RnsGaloisKey::CreateFromKeyComponents(
          gk_pads_, std::move(gk_key_bs), /*power=*/5, &rns_gadget_,
          rns_moduli_, prng_seed_gk_pad_, params_.prng_type));
  auto shared_gk = std::make_shared<const RnsGaloisKey>(std::move(gk));
  std::lock_guard<std::mutex> lock(gk_cache_mutex_);
  auto inserted = gk_cache_.emplace(
      std::string(session_id), SessionKeyState{std::move(shared_gk), 0});
  if (!inserted.second) {
    return absl::AlreadyExistsError("Session ID is already initialized.");
  }
  return absl::OkStatus();
}

template <typename RlweInteger>
void Server<RlweInteger>::RemoveSession(absl::string_view session_id) const {
  std::lock_guard<std::mutex> lock(gk_cache_mutex_);
  gk_cache_.erase(std::string(session_id));
}

template <typename RlweInteger>
void Server<RlweInteger>::ClearSessionCache() const {
  std::lock_guard<std::mutex> lock(gk_cache_mutex_);
  gk_cache_.clear();
}

template <typename RlweInteger>
absl::StatusOr<LinPirResponse> Server<RlweInteger>::HandleRequest(
    const RnsCiphertext& ct_query, const RnsGaloisKey& gk) const {
  // Preserve the full-ciphertext API for callers that do not use the
  // preprocessed public-component pool.
  if (query_pad_states_.empty()) {
    int num_rotations = params_.rows_per_block / 2;
    std::vector<RnsCiphertext> ct_rotated_queries;
    ct_rotated_queries.reserve(num_rotations);
    ct_rotated_queries.push_back(ct_query);
    for (int i = 1; i < num_rotations; ++i) {
      RLWE_ASSIGN_OR_RETURN(
          RnsCiphertext ct_sub,
          ct_rotated_queries[i - 1].Substitute(/*substitution_power=*/5));
      RLWE_ASSIGN_OR_RETURN(RnsCiphertext ct_rot, gk.ApplyTo(ct_sub));
      ct_rotated_queries.push_back(std::move(ct_rot));
    }

    LinPirResponse response;
    for (const auto* database : databases_) {
      RLWE_ASSIGN_OR_RETURN(std::vector<RnsCiphertext> ct_blocks,
                            database->InnerProductWith(ct_rotated_queries));
      LinPirResponse::EncryptedInnerProduct inner_product;
      for (const auto& ct : ct_blocks) {
        RLWE_ASSIGN_OR_RETURN(RnsPolynomial ct_b, ct.Component(0));
        RLWE_ASSIGN_OR_RETURN(*inner_product.add_ct_b_blocks(),
                              ct_b.Serialize(rns_moduli_));
      }
      *response.add_ct_inner_products() = std::move(inner_product);
    }
    return response;
  }
  RLWE_ASSIGN_OR_RETURN(const QueryPadState* pad_state, PadStateForToken(1));
  return HandleRequestWithPadState(ct_query, gk, *pad_state);
}

template <typename RlweInteger>
absl::StatusOr<LinPirResponse> Server<RlweInteger>::HandleRequestWithPadState(
    const RnsCiphertext& ct_query, const RnsGaloisKey& gk,
    const QueryPadState& pad_state) const {
  
  // Compute all rotations of the query vector.
  int num_rotations = params_.rows_per_block / 2;
  std::vector<RnsCiphertext> ct_rotated_queries;
  ct_rotated_queries.reserve(num_rotations);
  ct_rotated_queries.push_back(std::move(ct_query));
  
  for (int i = 1; i < num_rotations; ++i) {
    RLWE_ASSIGN_OR_RETURN(RnsCiphertext ct_sub,
                          ct_rotated_queries[i - 1].Substitute(5));
    
    RLWE_ASSIGN_OR_RETURN(RnsCiphertext ct_rot,
                          gk.ApplyToWithRandomPad(
                              ct_sub, pad_state.ct_sub_pad_digits[i - 1],
                              pad_state.ct_pads[i]));
    ct_rotated_queries.push_back(std::move(ct_rot));
  }

  // Compute inner products with the databases and serialize.
  LinPirResponse response;
  for (int database_index = 0; database_index < databases_.size();
       ++database_index) {
    const auto* database = databases_[database_index];
    LinPirResponse::EncryptedInnerProduct inner_product;
    
    RLWE_ASSIGN_OR_RETURN(std::vector<RnsCiphertext> ct_blocks,
                          database->InnerProductWithPads(
                              ct_rotated_queries,
                              pad_state.response_pads[database_index]));
                          
    for (auto const& ct : ct_blocks) {
      RLWE_ASSIGN_OR_RETURN(RnsPolynomial ct_b, ct.Component(0));
      RLWE_ASSIGN_OR_RETURN(*inner_product.add_ct_b_blocks(),
                        ct_b.Serialize(rns_moduli_));
    }
    *response.add_ct_inner_products() = std::move(inner_product);
  }
  return response;
}

template <typename RlweInteger>
absl::StatusOr<LinPirResponse> Server<RlweInteger>::HandleRequest(
    const ::rlwe::SerializedRnsPolynomial& proto_ct_query_b,
    const google::protobuf::RepeatedPtrField<::rlwe::SerializedRnsPolynomial>&
        proto_gk_key_bs) const {
  RLWE_ASSIGN_OR_RETURN(const QueryPadState* pad_state, PadStateForToken(1));

  // Deserialize the "b" components from request and build the query ciphertext
  // and the Galois key.
  RLWE_ASSIGN_OR_RETURN(
      RnsPolynomial ct_query_b,
      RnsPolynomial::Deserialize(proto_ct_query_b, rns_moduli_));
  RnsCiphertext ct_query({std::move(ct_query_b), pad_state->ct_pads[0]},
                         rns_moduli_,
                         /*power_of_s=*/1, /*error=*/0, &rns_error_params_,
                         rns_context_);

  std::vector<RnsPolynomial> gk_key_bs;
  gk_key_bs.reserve(proto_gk_key_bs.size());
  for (int i = 0; i < proto_gk_key_bs.size(); ++i) {
    RLWE_ASSIGN_OR_RETURN(
        RnsPolynomial gk_key_b,
        RnsPolynomial::Deserialize(proto_gk_key_bs[i], rns_moduli_));
    gk_key_bs.push_back(std::move(gk_key_b));
  }
  RLWE_ASSIGN_OR_RETURN(
      RnsGaloisKey gk,
      RnsGaloisKey::CreateFromKeyComponents(
          gk_pads_, std::move(gk_key_bs), /*power=*/5, &rns_gadget_,
          rns_moduli_, prng_seed_gk_pad_, params_.prng_type));

  // Compute all rotations of the query vector.
  int num_rotations = params_.rows_per_block / 2;
  std::vector<RnsCiphertext> ct_rotated_queries;
  ct_rotated_queries.reserve(num_rotations);
  ct_rotated_queries.push_back(std::move(ct_query));
  for (int i = 1; i < num_rotations; ++i) {
    RLWE_ASSIGN_OR_RETURN(RnsCiphertext ct_sub,
                          ct_rotated_queries[i - 1].Substitute(5));
    RLWE_ASSIGN_OR_RETURN(RnsCiphertext ct_rot,
                          gk.ApplyToWithRandomPad(
                              ct_sub, pad_state->ct_sub_pad_digits[i - 1],
                              pad_state->ct_pads[i]));
    ct_rotated_queries.push_back(std::move(ct_rot));
  }

  // Compute inner products with the databases and serialize them.
  LinPirResponse response;
  response.mutable_ct_inner_products()->Reserve(databases_.size());
  for (int database_index = 0; database_index < databases_.size();
       ++database_index) {
    const auto* database = databases_[database_index];
    RLWE_ASSIGN_OR_RETURN(
        std::vector<RnsCiphertext> ct_blocks,
        database->InnerProductWithPads(
            ct_rotated_queries, pad_state->response_pads[database_index]));
    LinPirResponse::EncryptedInnerProduct inner_product;
    //inner_product.mutable_ct_blocks()->Reserve(ct_blocks.size());
    inner_product.mutable_ct_b_blocks()->Reserve(ct_blocks.size());
    for (auto const& ct : ct_blocks) {
      //RLWE_ASSIGN_OR_RETURN(*inner_product.add_ct_blocks(), ct.Serialize());
      //RLWE_ASSIGN_OR_RETURN(*inner_product.add_ct_b_blocks(), ct.Serialize());
      RLWE_ASSIGN_OR_RETURN(RnsPolynomial ct_b, ct.Component(0));
      RLWE_ASSIGN_OR_RETURN(*inner_product.add_ct_b_blocks(),
                        ct_b.Serialize(rns_moduli_));
    }
    *response.add_ct_inner_products() = std::move(inner_product);
  }
  return response;
}

template <typename RlweInteger>
absl::StatusOr<LinPirResponse> Server<RlweInteger>::GetResponsePads() const {
  return GetResponsePads(1);
}

template <typename RlweInteger>
absl::StatusOr<LinPirResponse> Server<RlweInteger>::GetResponsePads(
    uint64_t query_token) const {
  if (databases_.empty() || query_pad_states_.empty()) {
    return absl::FailedPreconditionError(
        "Server has not been preprocessed to get response pads.");
  }
  RLWE_ASSIGN_OR_RETURN(const QueryPadState* pad_state,
                        PadStateForToken(query_token));

  LinPirResponse response_pads;
  response_pads.mutable_ct_inner_products()->Reserve(databases_.size());
  for (int database_index = 0; database_index < databases_.size();
       ++database_index) {
    LinPirResponse::EncryptedInnerProduct inner_product;
    const auto& pad_inner_products =
        pad_state->response_pads[database_index];
    inner_product.mutable_ct_b_blocks()->Reserve(pad_inner_products.size());
    for (const auto& pad : pad_inner_products) {
      RLWE_ASSIGN_OR_RETURN(*inner_product.add_ct_b_blocks(),
                            pad.Serialize(rns_moduli_));
    }
    *response_pads.add_ct_inner_products() = std::move(inner_product);
  }
  return response_pads;
}

template <typename RlweInteger>
absl::StatusOr<LinPirResponse> Server<RlweInteger>::HandleRequest(
    const LinPirRequest& request) const {
  if (!request.has_ct_query_b()) {
    return absl::InvalidArgumentError("Missing ct_query_b in request.");
  }
  uint64_t query_token = request.has_query_token() ? request.query_token() : 1;
  RLWE_ASSIGN_OR_RETURN(const QueryPadState* pad_state,
                        PadStateForToken(query_token));
  RLWE_ASSIGN_OR_RETURN(
      RnsPolynomial ct_query_b,
      RnsPolynomial::Deserialize(request.ct_query_b(), rns_moduli_));

  RnsCiphertext ct_query(
      {std::move(ct_query_b), pad_state->ct_pads[0]}, rns_moduli_,
                         /*power_of_s=*/1, /*error=*/0, &rns_error_params_,
                         rns_context_);

  // The legacy stateless API may still carry a Galois key with the query.
  // Secure sessions install it separately through CacheGaloisKey().
  if (request.gk_key_bs_size() > 0) {
    std::vector<RnsPolynomial> gk_key_bs;
    gk_key_bs.reserve(request.gk_key_bs_size());
    for (const auto& proto_poly : request.gk_key_bs()) {
      RLWE_ASSIGN_OR_RETURN(
          RnsPolynomial gk_key_b,
          RnsPolynomial::Deserialize(proto_poly, rns_moduli_));
      gk_key_bs.push_back(std::move(gk_key_b));
    }

    RLWE_ASSIGN_OR_RETURN(
        RnsGaloisKey gk,
        RnsGaloisKey::CreateFromKeyComponents(
            gk_pads_, std::move(gk_key_bs), /*power=*/5, &rns_gadget_,
            rns_moduli_, prng_seed_gk_pad_, params_.prng_type));

    return HandleRequestWithPadState(ct_query, gk, *pad_state);
  }

  if (!request.has_client_id()) {
    return absl::InvalidArgumentError("Missing Galois Key and Session ID.");
  }
  std::shared_ptr<const RnsGaloisKey> gk;
  {
    std::lock_guard<std::mutex> lock(gk_cache_mutex_);
    auto it = gk_cache_.find(request.client_id());
    if (it == gk_cache_.end()) {
      return absl::FailedPreconditionError(
          "Session key not found or expired for session ID: " +
          request.client_id());
    }
    if (query_token <= it->second.last_accepted_token) {
      return absl::AlreadyExistsError(
          "Query token has already been consumed for this session.");
    }
    it->second.last_accepted_token = query_token;
    gk = it->second.galois_key;
  }
  return HandleRequestWithPadState(ct_query, *gk, *pad_state);
}

template class Server<Uint32>;
template class Server<Uint64>;

}  // namespace linpir
}  // namespace hintless_pir
