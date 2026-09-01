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

#include "hintless_simplepir/server.h"

#include <algorithm>
#include <cstddef>
#include <iterator>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "Eigen/Core"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "hintless_simplepir/database_hwy.h"
#include "hintless_simplepir/parameters.h"
#include "hintless_simplepir/serialization.pb.h"
#include "hintless_simplepir/utils.h"
#include "lwe/lwe_symmetric_encryption.h"
#include "lwe/types.h"
#include "shell_encryption/prng/single_thread_chacha_prng.h"
#include "shell_encryption/prng/single_thread_hkdf_prng.h"
#include "shell_encryption/status_macros.h"

namespace hintless_pir {
namespace hintless_simplepir {

namespace {

// Returns an error if `params` uses an invalid PRNG type.
inline absl::Status CheckForValidPrngType(const Parameters& params) {
  if (!(params.prng_type == rlwe::PRNG_TYPE_HKDF ||
        params.prng_type == rlwe::PRNG_TYPE_CHACHA)) {
    return absl::InvalidArgumentError("Invalid PRNG type in `params`.");
  }
  if (params.session_pool_capacity <= 0) {
    return absl::InvalidArgumentError(
        "`session_pool_capacity` must be positive.");
  }
  return absl::OkStatus();
}

}  // namespace

absl::StatusOr<std::unique_ptr<Server>> Server::Create(
    const Parameters& params) {
  RLWE_RETURN_IF_ERROR(CheckForValidPrngType(params));

  // Create RLWE contexts, one per plaintext modulus in `ts`.
  auto const& rlwe_params = params.linpir_params;
  int num_linpir_instances = rlwe_params.ts.size();
  std::vector<std::unique_ptr<const RlweRnsContext>> rlwe_contexts;
  rlwe_contexts.reserve(num_linpir_instances);
  for (int i = 0; i < num_linpir_instances; ++i) {
    RLWE_ASSIGN_OR_RETURN(
        auto rlwe_context,
        RlweRnsContext::CreateForBfvFiniteFieldEncoding(
            rlwe_params.log_n, rlwe_params.qs, /*ps=*/{}, rlwe_params.ts[i]));
    rlwe_contexts.push_back(
        std::make_unique<const RlweRnsContext>(std::move(rlwe_context)));
  }

  // Create a Database object holding the database and hint matrices.
  RLWE_ASSIGN_OR_RETURN(auto database, Database::Create(params));

  return absl::WrapUnique(
      new Server(params, std::move(database), std::move(rlwe_contexts)));
}

absl::StatusOr<std::unique_ptr<Server>> Server::CreateWithRandomDatabaseRecords(
    const Parameters& params) {
  RLWE_RETURN_IF_ERROR(CheckForValidPrngType(params));

  // Create RLWE contexts, one per plaintext modulus in `ts`.
  auto const& rlwe_params = params.linpir_params;
  int num_linpir_instances = rlwe_params.ts.size();
  std::vector<std::unique_ptr<const RlweRnsContext>> rlwe_contexts;
  rlwe_contexts.reserve(num_linpir_instances);
  for (int i = 0; i < num_linpir_instances; ++i) {
    RLWE_ASSIGN_OR_RETURN(
        auto rlwe_context,
        RlweRnsContext::CreateForBfvFiniteFieldEncoding(
            rlwe_params.log_n, rlwe_params.qs, /*ps=*/{}, rlwe_params.ts[i]));
    rlwe_contexts.push_back(
        std::make_unique<const RlweRnsContext>(std::move(rlwe_context)));
  }

  // Create a Databas holding random records.
  RLWE_ASSIGN_OR_RETURN(auto database, Database::CreateRandom(params));

  return absl::WrapUnique(
      new Server(params, std::move(database), std::move(rlwe_contexts)));
}

absl::Status Server::GeneratePublicParams() {
  int num_linpir_instances = params_.linpir_params.ts.size();
  prng_seed_linpir_ct_pad_pool_.assign(
      params_.session_pool_capacity,
      std::vector<std::string>(num_linpir_instances));
  if (params_.prng_type == rlwe::PRNG_TYPE_HKDF) {
    RLWE_ASSIGN_OR_RETURN(prng_seed_lwe_query_pad_,
                          rlwe::SingleThreadHkdfPrng::GenerateSeed());
    RLWE_ASSIGN_OR_RETURN(database_version_,
                          rlwe::SingleThreadHkdfPrng::GenerateSeed());
    for (int token = 0; token < params_.session_pool_capacity; ++token) {
      for (int i = 0; i < num_linpir_instances; ++i) {
        RLWE_ASSIGN_OR_RETURN(
            prng_seed_linpir_ct_pad_pool_[token][i],
            rlwe::SingleThreadHkdfPrng::GenerateSeed());
      }
    }
    RLWE_ASSIGN_OR_RETURN(prng_seed_linpir_gk_pad_,
                          rlwe::SingleThreadHkdfPrng::GenerateSeed());
    // Generate the LWE "A" matrix.
    RLWE_ASSIGN_OR_RETURN(auto prng, rlwe::SingleThreadHkdfPrng::Create(
                                         prng_seed_lwe_query_pad_));
    RLWE_ASSIGN_OR_RETURN(
        auto pad,
        lwe::ExpandPad(params_.db_cols, params_.lwe_secret_dim, prng.get()));
    lwe_query_pad_ = std::make_unique<const lwe::Matrix>(std::move(pad));
  } else {
    RLWE_ASSIGN_OR_RETURN(prng_seed_lwe_query_pad_,
                          rlwe::SingleThreadChaChaPrng::GenerateSeed());
    RLWE_ASSIGN_OR_RETURN(database_version_,
                          rlwe::SingleThreadChaChaPrng::GenerateSeed());
    for (int token = 0; token < params_.session_pool_capacity; ++token) {
      for (int i = 0; i < num_linpir_instances; ++i) {
        RLWE_ASSIGN_OR_RETURN(
            prng_seed_linpir_ct_pad_pool_[token][i],
            rlwe::SingleThreadChaChaPrng::GenerateSeed());
      }
    }
    RLWE_ASSIGN_OR_RETURN(prng_seed_linpir_gk_pad_,
                          rlwe::SingleThreadChaChaPrng::GenerateSeed());

    RLWE_ASSIGN_OR_RETURN(auto prng, rlwe::SingleThreadChaChaPrng::Create(
                                         prng_seed_lwe_query_pad_));
    RLWE_ASSIGN_OR_RETURN(
        auto pad,
        lwe::ExpandPad(params_.db_cols, params_.lwe_secret_dim, prng.get()));
    lwe_query_pad_ = std::make_unique<const lwe::Matrix>(std::move(pad));
  }
  ++pool_epoch_;
  return absl::OkStatus();
}

namespace {

// Given `matrix` with mod-q entries, returns `matrix` mod p, where modular
// numbers are in balanced representation.
template <typename Integer>
std::vector<std::vector<Integer>> EncodeLweMatrix(
    const Database::LweMatrix& matrix, Integer q, Integer p) {
  Integer q_half = q >> 1;
  int num_rows = matrix.size();
  int num_cols = matrix[0].size();
  std::vector<std::vector<Integer>> matrix_mod_p(num_rows);
  for (int i = 0; i < num_rows; ++i) {
    matrix_mod_p[i].reserve(num_cols);
    for (int j = 0; j < num_cols; ++j) {
      Integer x = static_cast<Integer>(matrix[i][j]);
      matrix_mod_p[i].push_back(ConvertModulus(x, q, p, q_half));
    }
  }
  return matrix_mod_p;
}

}  // namespace

absl::Status Server::Preprocess() {
  preprocessed_ = false;
  // A new database version invalidates every existing session and unused
  // public-component token.
  {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    sessions_.clear();
  }

  // Refresh the PRNG seeds.
  RLWE_RETURN_IF_ERROR(GeneratePublicParams());

  // Make sure the hint is up to date.
  RLWE_RETURN_IF_ERROR(database_->UpdateLweQueryPad(lwe_query_pad_.get()));
  RLWE_RETURN_IF_ERROR(database_->UpdateHints());

  RlweInteger lwe_modulus = RlweInteger{1} << params_.lwe_modulus_bit_size;
  size_t num_shards = database_->NumShards();

  // Create LinPir databases (holding the preprocessed hints) and servers.
  linpir_servers_.clear();
  linpir_servers_.resize(rlwe_contexts_.size());
  linpir_databases_.clear();
  linpir_databases_.resize(rlwe_contexts_.size());
  for (int k = 0; k < rlwe_contexts_.size(); ++k) {
    RlweInteger plaintext_modulus = rlwe_contexts_[k]->PlaintextModulus();

    // One LinPir database per shard, for the current plaintext modulus.
    std::vector<std::unique_ptr<LinPirDatabase>> linpir_databases_mod_tk;
    linpir_databases_mod_tk.reserve(num_shards);
    for (const Database::LweMatrix& hint : database_->Hints()) {
      std::vector<std::vector<RlweInteger>> hint_mod_tk =
          EncodeLweMatrix(hint, lwe_modulus, plaintext_modulus);
      RLWE_ASSIGN_OR_RETURN(
          auto linpir_database,
          LinPirDatabase::Create(params_.linpir_params, rlwe_contexts_[k].get(),
                                 hint_mod_tk));
      linpir_databases_mod_tk.push_back(std::move(linpir_database));
    }
    std::vector<LinPirDatabase*> linpir_databases_ptrs;
    std::transform(linpir_databases_mod_tk.begin(),
                   linpir_databases_mod_tk.end(),
                   std::back_inserter(linpir_databases_ptrs),
                   [](auto& ptr) { return ptr.get(); });
    std::vector<std::string> token_seeds;
    token_seeds.reserve(params_.session_pool_capacity);
    for (int token = 0; token < params_.session_pool_capacity; ++token) {
      token_seeds.push_back(prng_seed_linpir_ct_pad_pool_[token][k]);
    }
    RLWE_ASSIGN_OR_RETURN(
        auto linpir_server_mod_tk,
        LinPirServer::Create(params_.linpir_params, rlwe_contexts_[k].get(),
                             linpir_databases_ptrs, token_seeds,
                             prng_seed_linpir_gk_pad_));
    RLWE_RETURN_IF_ERROR(linpir_server_mod_tk->Preprocess());

    linpir_databases_[k] = std::move(linpir_databases_mod_tk);
    linpir_servers_[k] = std::move(linpir_server_mod_tk);
  }
  // Export the matching public response component for every token and CRT
  // instance. The client consumes this pool one entry at a time.
  linpir_response_pad_pool_.assign(params_.session_pool_capacity, {});
  for (int token = 0; token < params_.session_pool_capacity; ++token) {
    linpir_response_pad_pool_[token].reserve(linpir_servers_.size());
    for (int k = 0; k < linpir_servers_.size(); ++k) {
      RLWE_ASSIGN_OR_RETURN(
          auto response_pads,
          linpir_servers_[k]->GetResponsePads(token + 1));
      linpir_response_pad_pool_[token].push_back(std::move(response_pads));
    }
  }
  preprocessed_ = true;
  return absl::OkStatus();
}

absl::StatusOr<HintlessPirSessionInitResponse> Server::InitializeSession(
    const HintlessPirSessionInitRequest& request) {
  if (!IsPreprocessed()) {
    return absl::FailedPreconditionError("Server has not been preprocessed.");
  }
  if (!request.has_client_id() || request.client_id().empty()) {
    return absl::InvalidArgumentError("Missing session ID.");
  }
  if (!request.has_database_version() ||
      request.database_version() != database_version_ ||
      !request.has_pool_epoch() || request.pool_epoch() != pool_epoch_) {
    return absl::FailedPreconditionError(
        "Session initialization uses a stale database version or pool epoch.");
  }
  if (request.linpir_gk_bs_size() == 0) {
    return absl::InvalidArgumentError("Missing session Galois key.");
  }
  std::lock_guard<std::mutex> lock(sessions_mutex_);
  if (sessions_.find(request.client_id()) != sessions_.end()) {
    return absl::AlreadyExistsError("Session ID is already initialized.");
  }

  int cached_servers = 0;
  for (const auto& linpir_server : linpir_servers_) {
    absl::Status status = linpir_server->CacheGaloisKey(
        request.client_id(), request.linpir_gk_bs());
    if (!status.ok()) {
      for (int i = 0; i < cached_servers; ++i) {
        linpir_servers_[i]->RemoveSession(request.client_id());
      }
      return status;
    }
    ++cached_servers;
  }
  sessions_.emplace(request.client_id(), SessionState{});

  HintlessPirSessionInitResponse response;
  response.set_client_id(request.client_id());
  response.set_database_version(database_version_);
  response.set_pool_epoch(pool_epoch_);
  response.set_pool_capacity(params_.session_pool_capacity);
  return response;
}

absl::StatusOr<HintlessPirResponse> Server::HandleRequest(
    const HintlessPirRequest& request) {
  if (!IsPreprocessed()) {
    return absl::FailedPreconditionError("Server has not been preprocessed.");
  }
  if (!request.has_client_id() || request.client_id().empty()) {
    return absl::InvalidArgumentError("Missing session ID.");
  }
  if (!request.has_database_version() ||
      request.database_version() != database_version_ ||
      !request.has_pool_epoch() || request.pool_epoch() != pool_epoch_) {
    return absl::FailedPreconditionError(
        "Request uses a stale database version or pool epoch.");
  }
  if (!request.has_query_token() || request.query_token() == 0 ||
      request.query_token() > params_.session_pool_capacity) {
    return absl::InvalidArgumentError("Request token is outside the pool.");
  }
  if (request.linpir_gk_bs_size() != 0) {
    return absl::InvalidArgumentError(
        "Online requests must not carry a Galois key; initialize the session "
        "first.");
  }
  {
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    auto session_it = sessions_.find(request.client_id());
    if (session_it == sessions_.end()) {
      return absl::FailedPreconditionError(
          "Session is not initialized or was invalidated.");
    }
    if (request.query_token() <= session_it->second.last_accepted_token) {
      return absl::AlreadyExistsError(
          "Query token has already been consumed.");
    }

    // Compare and consume atomically. If any later operation fails, the token
    // remains burned and a retry must use a larger token.
    session_it->second.last_accepted_token = request.query_token();
  }

  HintlessPirResponse response;
  response.set_client_id(request.client_id());
  response.set_database_version(database_version_);
  response.set_pool_epoch(pool_epoch_);
  response.set_query_token(request.query_token());
  // Handle the LWE part of the request.
  Database::LweVector ct_query_vector =
      DeserializeLweCiphertext(request.ct_query_vector());
  RLWE_ASSIGN_OR_RETURN(std::vector<Database::LweVector> ct_records,
                        database_->InnerProductWith(ct_query_vector));
  for (auto& ct_record : ct_records) {
    *response.add_ct_records() = SerializeLweCiphertext(ct_record);
  }

  // Handle the LinPIR requests.
  int num_linpir_requests = request.linpir_ct_bs_size();
  if (num_linpir_requests != linpir_servers_.size()) {
    return absl::InvalidArgumentError(
        "`request` contains unexpected number of LinPir requests.");
  }
  
  for (int k = 0; k < num_linpir_requests; ++k) {
    LinPirRequest linpir_req;
    *linpir_req.mutable_ct_query_b() = request.linpir_ct_bs(k);
    linpir_req.set_client_id(request.client_id());
    linpir_req.set_query_token(request.query_token());
    RLWE_ASSIGN_OR_RETURN(LinPirResponse linpir_response,
                          linpir_servers_[k]->HandleRequest(linpir_req));
                          
    *response.add_linpir_responses() = std::move(linpir_response);
  }
  return response;
}

HintlessPirServerPublicParams Server::GetPublicParams() const {
  HintlessPirServerPublicParams output;
  output.set_prng_seed_lwe_query_pad(prng_seed_lwe_query_pad_);
  for (const auto& token_seeds : prng_seed_linpir_ct_pad_pool_) {
    for (const auto& prng_seed : token_seeds) {
      *output.add_prng_seed_linpir_ct_pads() = prng_seed;
    }
  }
  output.set_prng_seed_linpir_gk_pad(prng_seed_linpir_gk_pad_);
  for (const auto& token_pads : linpir_response_pad_pool_) {
    for (const auto& pads : token_pads) {
      *output.add_linpir_response_hints() = pads;
    }
  }
  output.set_database_version(database_version_);
  output.set_pool_epoch(pool_epoch_);
  output.set_pool_capacity(params_.session_pool_capacity);
  return output;
}

}  // namespace hintless_simplepir
}  // namespace hintless_pir
