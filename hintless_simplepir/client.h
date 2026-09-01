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

#ifndef HINTLESS_PIR_HINTLESS_SIMPLEPIR_CLIENT_H_
#define HINTLESS_PIR_HINTLESS_SIMPLEPIR_CLIENT_H_

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "hintless_simplepir/parameters.h"
#include "hintless_simplepir/serialization.pb.h"
#include "linpir/client.h"
#include "linpir/serialization.pb.h"
#include "lwe/types.h"
#include "shell_encryption/montgomery.h"
#include "shell_encryption/rns/rns_context.h"
#include "shell_encryption/rns/rns_modulus.h"

namespace hintless_pir {
namespace hintless_simplepir {

// The client part of the HintlessPir protocol.
class Client {
 public:
  // Creates a client from the given protocol parameters `params` and the
  // server's public parameters `public_params`.
  static absl::StatusOr<std::unique_ptr<Client>> Create(
      const Parameters& params,
      const HintlessPirServerPublicParams& public_params);

  // Returns the request for accessing database[index].
  absl::StatusOr<HintlessPirRequest> GenerateRequest(int64_t index);

  // Returns the setup message that installs the session-scoped Galois key.
  // Sending the same setup message does not consume a query token.
  absl::StatusOr<HintlessPirSessionInitRequest> GenerateSessionInitRequest();

  // Confirms that the server installed this client's session key. Online
  // queries remain disabled until this acknowledgement is validated.
  absl::Status AcceptSessionInitResponse(
      const HintlessPirSessionInitResponse& response);

  // Burns an outstanding token after a timeout or cancelled transport. The
  // next request uses a fresh token and fresh query randomness.
  absl::Status AbandonOutstandingRequest();

  // Returns the retrieved record from the server response.
  absl::StatusOr<std::string> RecoverRecord(
      const HintlessPirResponse& response);

 private:
  using RlweInteger = Parameters::RlweInteger;
  using RlweModularInt = rlwe::MontgomeryInt<RlweInteger>;
  using RlweRnsContext = rlwe::RnsContext<RlweModularInt>;
  using RlwePrimeModulus = rlwe::PrimeModulus<RlweModularInt>;
  using LinPirClient = linpir::Client<RlweInteger>;

  // HintlessPir client state, which is cached for each request until the
  // corresponding response is received:
  //
  // 1) as in SimplePIR, a pair of indices (row_idx, col_idx) representing the
  // client's desired query index i = (row_idx * cols) + col_idx.
  //
  // 2) the one-time token selecting the matching query and response pads.
  struct ClientState {
    int64_t row_idx;
    int64_t col_idx;
    uint64_t query_token;
  };

  explicit Client(
      Parameters params,
      const HintlessPirServerPublicParams& public_params,
      std::vector<std::unique_ptr<const RlweRnsContext>> rlwe_contexts,
      std::vector<const RlwePrimeModulus*> rlwe_moduli,
      std::vector<std::unique_ptr<LinPirClient>> linpir_clients,
      RlweRnsContext crt_context)
      : params_(std::move(params)),
        prng_seed_lwe_query_pad_(
                   std::string(public_params.prng_seed_lwe_query_pad())),
        rlwe_contexts_(std::move(rlwe_contexts)),
        rlwe_moduli_(std::move(rlwe_moduli)),
        linpir_clients_(std::move(linpir_clients)),
        crt_context_(std::move(crt_context)),
        linpir_ct_pad_seeds_(
            public_params.prng_seed_linpir_ct_pads().begin(),
            public_params.prng_seed_linpir_ct_pads().end()),
        linpir_response_pads_(
            public_params.linpir_response_hints().begin(),
            public_params.linpir_response_hints().end()),
        database_version_(public_params.database_version()),
        pool_epoch_(public_params.pool_epoch()),
        pool_capacity_(public_params.pool_capacity()) {}

  static std::vector<RlweInteger> EncodeLweVector(const lwe::Vector& lwe_vector,
                                                  RlweInteger lwe_modulus,
                                                  RlweInteger encode_modulus);

  // Encrypts the LWE secret vector using LinPir clients and update `request`
  // with the LinPir requests.
  absl::Status GenerateLinPirRequestInPlace(
      HintlessPirRequest& request, const lwe::Vector& lwe_secret,
      uint64_t query_token) const;

  // CRT interpolates the LinPir responses to recover the LWE decryption parts,
  // which are the inner products hint * LWE secrets.
  absl::StatusOr<std::vector<lwe::Vector>> RecoverLweDecryptionParts(
      const HintlessPirResponse& response, uint64_t query_token) const;

  const Parameters params_;

  // PRNG seed for generating the "A" matrix for LWE query ciphertext.
  std::string prng_seed_lwe_query_pad_;

  const std::vector<std::unique_ptr<const RlweRnsContext>> rlwe_contexts_;

  // The RLWE RNS moduli common to all LinPir clients.
  const std::vector<const RlwePrimeModulus*> rlwe_moduli_;

  const std::vector<std::unique_ptr<LinPirClient>> linpir_clients_;

  const RlweRnsContext crt_context_;

  // Token-major ciphertext pad seeds and matching response components.
  std::vector<std::string> linpir_ct_pad_seeds_;
  std::vector<hintless_pir::LinPirResponse> linpir_response_pads_;

  std::string database_version_;
  uint64_t pool_epoch_ = 0;
  uint64_t pool_capacity_ = 0;
  uint64_t next_query_token_ = 1;
  bool has_outstanding_request_ = false;
  bool session_init_generated_ = false;
  bool session_ready_ = false;
  HintlessPirSessionInitRequest cached_session_init_request_;
  mutable std::mutex request_mutex_;

  // Per request state.
  ClientState state_;

  std::string client_id_;
  std::string session_linpir_sk_seed_;
};

}  // namespace hintless_simplepir
}  // namespace hintless_pir

#endif  // HINTLESS_PIR_HINTLESS_SIMPLEPIR_CLIENT_H_
