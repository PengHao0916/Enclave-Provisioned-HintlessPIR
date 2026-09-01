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

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "hintless_simplepir/parameters.h"
#include "hintless_simplepir/utils.h"
#include "linpir/parameters.h"
#include "lwe/types.h"
#include "shell_encryption/prng/single_thread_hkdf_prng.h"
#include "shell_encryption/testing/status_matchers.h"
#include "shell_encryption/testing/status_testing.h"

namespace hintless_pir {
namespace hintless_simplepir {
namespace {

using rlwe::testing::StatusIs;
using RlweInteger = Parameters::RlweInteger;
using Prng = rlwe::SingleThreadHkdfPrng;

constexpr rlwe::PrngType kPrngType = rlwe::PRNG_TYPE_HKDF;
constexpr absl::string_view kPrngSeed =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const Parameters kParameters{
    .db_rows = 128,
    .db_cols = 32,
    .db_record_bit_size = 8,
    .lwe_secret_dim = 32,
    .lwe_modulus_bit_size = 32,
    .lwe_plaintext_bit_size = 8,
    .lwe_error_variance = 8,
    .linpir_params =
        linpir::RlweParameters<RlweInteger>{
            .log_n = 10,
            .qs = {536813569ULL},
            .ts = {12289, 65537},
            .gadget_log_bs = {8},
            .error_variance = 8,
            .prng_type = kPrngType,
            .rows_per_block = 512,
        },
    .prng_type = kPrngType,
};

HintlessPirServerPublicParams GenerateDummyPublicParams(
    const Parameters& params) {
  HintlessPirServerPublicParams public_params;
  public_params.set_prng_seed_lwe_query_pad(std::string(kPrngSeed));
  for (int token = 0; token < params.session_pool_capacity; ++token) {
    for (auto plaintext_modulus : params.linpir_params.ts) {
      (void)plaintext_modulus;
      *public_params.add_prng_seed_linpir_ct_pads() = std::string(kPrngSeed);
      public_params.add_linpir_response_hints();
    }
  }
  public_params.set_prng_seed_linpir_gk_pad(std::string(kPrngSeed));
  public_params.set_database_version("test-database-version");
  public_params.set_pool_epoch(1);
  public_params.set_pool_capacity(params.session_pool_capacity);
  return public_params;
}

TEST(Client, CreateFailsIfInvalidPrngType) {
  Parameters invalid_params = kParameters;
  invalid_params.prng_type = rlwe::PRNG_TYPE_INVALID;
  EXPECT_THAT(
      Client::Create(invalid_params, GenerateDummyPublicParams(invalid_params)),
      StatusIs(absl::StatusCode::kInvalidArgument,
               testing::HasSubstr("Invalid PRNG type")));
}

TEST(Client, CreateFailsIfInvalidPublicParams) {
  // Empty public params.
  HintlessPirServerPublicParams invalid_public_params;
  EXPECT_THAT(
      Client::Create(kParameters, invalid_public_params),
      StatusIs(absl::StatusCode::kInvalidArgument,
               testing::HasSubstr("invalid pool capacity")));
}

TEST(Client, Create) {
  auto public_params = GenerateDummyPublicParams(kParameters);
  ASSERT_OK_AND_ASSIGN(auto client, Client::Create(kParameters, public_params));
}

TEST(Client, GenerateRequestFailsIfIndexIsOutOfRange) {
  auto public_params = GenerateDummyPublicParams(kParameters);
  ASSERT_OK_AND_ASSIGN(auto client, Client::Create(kParameters, public_params));
  ASSERT_OK_AND_ASSIGN(auto init_request,
                       client->GenerateSessionInitRequest());
  HintlessPirSessionInitResponse init_response;
  init_response.set_client_id(init_request.client_id());
  init_response.set_database_version(init_request.database_version());
  init_response.set_pool_epoch(init_request.pool_epoch());
  init_response.set_pool_capacity(public_params.pool_capacity());
  ASSERT_OK(client->AcceptSessionInitResponse(init_response));

  EXPECT_THAT(client->GenerateRequest(-1),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       testing::HasSubstr("`index` out of range")));
  int64_t too_large_index = kParameters.db_rows * kParameters.db_cols + 1;
  EXPECT_THAT(client->GenerateRequest(too_large_index),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       testing::HasSubstr("`index` out of range")));
}

TEST(Client, SessionSetupAndOneTimeTokens) {
  auto public_params = GenerateDummyPublicParams(kParameters);
  ASSERT_OK_AND_ASSIGN(auto client, Client::Create(kParameters, public_params));

  ASSERT_OK_AND_ASSIGN(auto init_request,
                       client->GenerateSessionInitRequest());
  EXPECT_FALSE(init_request.client_id().empty());
  EXPECT_EQ(init_request.database_version(), public_params.database_version());
  EXPECT_EQ(init_request.pool_epoch(), public_params.pool_epoch());
  EXPECT_GT(init_request.linpir_gk_bs_size(), 0);
  ASSERT_OK_AND_ASSIGN(auto repeated_init_request,
                       client->GenerateSessionInitRequest());
  EXPECT_EQ(repeated_init_request.SerializeAsString(),
            init_request.SerializeAsString());

  EXPECT_THAT(client->GenerateRequest(1),
              StatusIs(absl::StatusCode::kFailedPrecondition,
                       testing::HasSubstr("not acknowledged")));
  HintlessPirSessionInitResponse init_response;
  init_response.set_client_id(init_request.client_id());
  init_response.set_database_version(init_request.database_version());
  init_response.set_pool_epoch(init_request.pool_epoch());
  init_response.set_pool_capacity(public_params.pool_capacity());
  ASSERT_OK(client->AcceptSessionInitResponse(init_response));

  ASSERT_OK_AND_ASSIGN(auto request1, client->GenerateRequest(1));
  EXPECT_EQ(request1.query_token(), 1);
  EXPECT_EQ(request1.linpir_gk_bs_size(), 0);
  EXPECT_THAT(client->GenerateRequest(2),
              StatusIs(absl::StatusCode::kFailedPrecondition,
                       testing::HasSubstr("already outstanding")));

  ASSERT_OK(client->AbandonOutstandingRequest());
  ASSERT_OK_AND_ASSIGN(auto request2, client->GenerateRequest(2));
  EXPECT_EQ(request2.query_token(), 2);
  ASSERT_OK(client->AbandonOutstandingRequest());
  EXPECT_THAT(client->GenerateRequest(3),
              StatusIs(absl::StatusCode::kResourceExhausted,
                       testing::HasSubstr("pool is exhausted")));
}

TEST(Client, RecoverRecordFailsIfInvalidResponse) {
  auto public_params = GenerateDummyPublicParams(kParameters);
  ASSERT_OK_AND_ASSIGN(auto client, Client::Create(kParameters, public_params));

  ASSERT_OK_AND_ASSIGN(auto init_request,
                       client->GenerateSessionInitRequest());
  HintlessPirSessionInitResponse init_response;
  init_response.set_client_id(init_request.client_id());
  init_response.set_database_version(init_request.database_version());
  init_response.set_pool_epoch(init_request.pool_epoch());
  init_response.set_pool_capacity(public_params.pool_capacity());
  ASSERT_OK(client->AcceptSessionInitResponse(init_response));
  ASSERT_OK_AND_ASSIGN(auto request, client->GenerateRequest(1));
  HintlessPirResponse empty_response;
  empty_response.set_client_id(request.client_id());
  empty_response.set_database_version(request.database_version());
  empty_response.set_pool_epoch(request.pool_epoch());
  empty_response.set_query_token(request.query_token());
  EXPECT_THAT(client->RecoverRecord(empty_response),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       testing::HasSubstr("`response` has incorrect size")));

  HintlessPirResponse no_linpir_response;
  no_linpir_response.set_client_id(request.client_id());
  no_linpir_response.set_database_version(request.database_version());
  no_linpir_response.set_pool_epoch(request.pool_epoch());
  no_linpir_response.set_query_token(request.query_token());
  *no_linpir_response.add_ct_records() =
      SerializeLweCiphertext(lwe::Vector::Zero(kParameters.db_rows));
  EXPECT_THAT(
      client->RecoverRecord(no_linpir_response),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          testing::HasSubstr(
              "`response` contains unexpected number of LinPir responses")));
}

}  // namespace
}  // namespace hintless_simplepir
}  // namespace hintless_pir
