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
#include <iostream>
#include <iomanip>
#include <memory>
#include <string>
#include <thread>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "hintless_simplepir/client.h"
#include "hintless_simplepir/database_hwy.h"
#include "hintless_simplepir/parameters.h"
#include "hintless_simplepir/server.h"
#include "linpir/parameters.h"
#include "shell_encryption/testing/status_testing.h"
#include "shell_encryption/testing/status_matchers.h"

namespace hintless_pir {
namespace hintless_simplepir {
namespace {

using RlweInteger = Parameters::RlweInteger;
using rlwe::testing::StatusIs;

const Parameters kParameters{
    .db_rows = 8,
    .db_cols = 8,
    .db_record_bit_size = 64,
    .lwe_secret_dim = 32,
    .lwe_modulus_bit_size = 32,
    .lwe_plaintext_bit_size = 8,
    .lwe_error_variance = 8,
    .linpir_params =
        linpir::RlweParameters<RlweInteger>{
            .log_n = 12,
            .qs = {35184371884033ULL, 35184371703809ULL},  // 90 bits
            .ts = {2056193, 1990657},                      // 42 bits
            .gadget_log_bs = {16, 16},
            .error_variance = 8,
            .prng_type = rlwe::PRNG_TYPE_HKDF,
            .rows_per_block = 8,
        },
    .prng_type = rlwe::PRNG_TYPE_HKDF,
};

TEST(HintlessSimplePir, EndToEndTest) {
  // Create server and fill in random database records.
  ASSERT_OK_AND_ASSIGN(auto server,
                       Server::CreateWithRandomDatabaseRecords(kParameters));

  // Preprocess the server and get public parameters.
  ASSERT_OK(server->Preprocess());
  auto public_params = server->GetPublicParams();

  // Create a client and issue request.
  ASSERT_OK_AND_ASSIGN(auto client, Client::Create(kParameters, public_params));
  ASSERT_OK_AND_ASSIGN(auto init_request,
                       client->GenerateSessionInitRequest());
  ASSERT_OK_AND_ASSIGN(auto init_response,
                       server->InitializeSession(init_request));
  ASSERT_OK(client->AcceptSessionInitResponse(init_response));
  ASSERT_OK_AND_ASSIGN(auto request, client->GenerateRequest(1));

  // Handle the request
  ASSERT_OK_AND_ASSIGN(auto response, server->HandleRequest(request));
  ASSERT_OK_AND_ASSIGN(auto record, client->RecoverRecord(response));

  const Database* database = server->GetDatabase();
  ASSERT_OK_AND_ASSIGN(auto expected, database->Record(1));
  std::cout << "\n[DEBUG-2] Verifying test comparison:" << std::endl;
  auto print_hex = [](const std::string& s, const char* title) {
  std::cout << "  " << title << " (hex): ";
  for (unsigned char c : s) {
    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)c;
  }
  std::cout << std::dec << std::endl;
};
  print_hex(record,   "Recovered 'record'");
  print_hex(expected, "Expected 'record'");
  EXPECT_EQ(record, expected);
}

TEST(HintlessSimplePir, EndToEndTestWithChaChaPrng) {
  // Use ChaCha PRNG in both LinPIR and SimplePIR sub-protocols.
  Parameters params = kParameters;
  params.linpir_params.prng_type = rlwe::PRNG_TYPE_CHACHA;
  params.prng_type = rlwe::PRNG_TYPE_CHACHA;

  // Create server and fill in random database records.
  ASSERT_OK_AND_ASSIGN(auto server,
                       Server::CreateWithRandomDatabaseRecords(params));

  // Preprocess the server and get public parameters.
  ASSERT_OK(server->Preprocess());
  auto public_params = server->GetPublicParams();

  // Create a client and issue request.
  ASSERT_OK_AND_ASSIGN(auto client, Client::Create(params, public_params));
  ASSERT_OK_AND_ASSIGN(auto init_request,
                       client->GenerateSessionInitRequest());
  ASSERT_OK_AND_ASSIGN(auto init_response,
                       server->InitializeSession(init_request));
  ASSERT_OK(client->AcceptSessionInitResponse(init_response));
  ASSERT_OK_AND_ASSIGN(auto request, client->GenerateRequest(1));

  // Handle the request
  ASSERT_OK_AND_ASSIGN(auto response, server->HandleRequest(request));
  ASSERT_OK_AND_ASSIGN(auto record, client->RecoverRecord(response));

  const Database* database = server->GetDatabase();
  ASSERT_OK_AND_ASSIGN(auto expected, database->Record(1));
  EXPECT_EQ(record, expected);
}

TEST(HintlessSimplePir, FreshPadsPreventCancellationAndReplay) {
  ASSERT_OK_AND_ASSIGN(auto server,
                       Server::CreateWithRandomDatabaseRecords(kParameters));
  ASSERT_OK(server->Preprocess());
  auto public_params = server->GetPublicParams();
  const int num_crt = kParameters.linpir_params.ts.size();
  ASSERT_EQ(public_params.pool_capacity(), 2);
  ASSERT_GE(public_params.prng_seed_linpir_ct_pads_size(), 2 * num_crt);
  EXPECT_NE(public_params.prng_seed_linpir_ct_pads(0),
            public_params.prng_seed_linpir_ct_pads(num_crt));

  ASSERT_OK_AND_ASSIGN(auto client, Client::Create(kParameters, public_params));
  ASSERT_OK_AND_ASSIGN(auto init_request,
                       client->GenerateSessionInitRequest());
  ASSERT_OK_AND_ASSIGN(auto init_response,
                       server->InitializeSession(init_request));
  ASSERT_OK(client->AcceptSessionInitResponse(init_response));

  ASSERT_OK_AND_ASSIGN(auto request1, client->GenerateRequest(1));
  EXPECT_EQ(request1.query_token(), 1);
  EXPECT_EQ(request1.linpir_gk_bs_size(), 0);
  ASSERT_OK_AND_ASSIGN(auto response1, server->HandleRequest(request1));
  EXPECT_THAT(server->HandleRequest(request1),
              StatusIs(absl::StatusCode::kAlreadyExists));
  ASSERT_OK_AND_ASSIGN(auto record1, client->RecoverRecord(response1));
  ASSERT_OK_AND_ASSIGN(auto expected1, server->GetDatabase()->Record(1));
  EXPECT_EQ(record1, expected1);

  ASSERT_OK_AND_ASSIGN(auto request2, client->GenerateRequest(2));
  EXPECT_EQ(request2.query_token(), 2);
  ASSERT_OK_AND_ASSIGN(auto response2, server->HandleRequest(request2));
  ASSERT_OK_AND_ASSIGN(auto record2, client->RecoverRecord(response2));
  ASSERT_OK_AND_ASSIGN(auto expected2, server->GetDatabase()->Record(2));
  EXPECT_EQ(record2, expected2);

  EXPECT_THAT(client->GenerateRequest(3),
              StatusIs(absl::StatusCode::kResourceExhausted));
}

TEST(HintlessSimplePir, ConcurrentReplayHasOnlyOneWinner) {
  ASSERT_OK_AND_ASSIGN(auto server,
                       Server::CreateWithRandomDatabaseRecords(kParameters));
  ASSERT_OK(server->Preprocess());
  ASSERT_OK_AND_ASSIGN(
      auto client, Client::Create(kParameters, server->GetPublicParams()));
  ASSERT_OK_AND_ASSIGN(auto init_request,
                       client->GenerateSessionInitRequest());
  ASSERT_OK_AND_ASSIGN(auto init_response,
                       server->InitializeSession(init_request));
  ASSERT_OK(client->AcceptSessionInitResponse(init_response));
  ASSERT_OK_AND_ASSIGN(auto request, client->GenerateRequest(1));

  absl::Status status1;
  absl::Status status2;
  std::thread thread1(
      [&] { status1 = server->HandleRequest(request).status(); });
  std::thread thread2(
      [&] { status2 = server->HandleRequest(request).status(); });
  thread1.join();
  thread2.join();

  int success_count = status1.ok() + status2.ok();
  int replay_count =
      (status1.code() == absl::StatusCode::kAlreadyExists) +
      (status2.code() == absl::StatusCode::kAlreadyExists);
  EXPECT_EQ(success_count, 1);
  EXPECT_EQ(replay_count, 1);
}

TEST(HintlessSimplePir, RejectsOutOfOrderAndStalePoolRequests) {
  ASSERT_OK_AND_ASSIGN(auto server,
                       Server::CreateWithRandomDatabaseRecords(kParameters));
  ASSERT_OK(server->Preprocess());
  ASSERT_OK_AND_ASSIGN(
      auto client, Client::Create(kParameters, server->GetPublicParams()));
  ASSERT_OK_AND_ASSIGN(auto init_request,
                       client->GenerateSessionInitRequest());
  ASSERT_OK_AND_ASSIGN(auto init_response,
                       server->InitializeSession(init_request));
  ASSERT_OK(client->AcceptSessionInitResponse(init_response));

  ASSERT_OK_AND_ASSIGN(auto request1, client->GenerateRequest(1));
  ASSERT_OK(client->AbandonOutstandingRequest());
  ASSERT_OK_AND_ASSIGN(auto request2, client->GenerateRequest(2));
  ASSERT_OK(server->HandleRequest(request2));
  EXPECT_THAT(server->HandleRequest(request1),
              StatusIs(absl::StatusCode::kAlreadyExists));

  ASSERT_OK(server->Preprocess());
  EXPECT_THAT(server->HandleRequest(request2),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

}  // namespace
}  // namespace hintless_simplepir
}  // namespace hintless_pir
