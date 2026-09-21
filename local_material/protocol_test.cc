#include "local_material/protocol.h"

#include <thread>
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "shell_encryption/testing/status_testing.h"

namespace hintless_pir::local_material {
namespace {

TEST(LocalMaterial, AdaptiveQueriesReuseOneStaticHintAndCanReplenish) {
  const auto params = DemoParameters();
  ASSERT_OK_AND_ASSIGN(auto server, PreparedServer::Create(params));
  const auto pub = server->PublicParams();
  ASSERT_EQ(pub.pool_capacity(), 1);
  ASSERT_EQ(pub.linpir_response_hints_size(), params.linpir_params.ts.size());
  ASSERT_OK_AND_ASSIGN(auto client, PreparedClient::Create(params, pub));
  LocalMaterialGenerator generator(params, MakeGeneratorConfig(params, pub));
  std::string previous_ct, previous_gk;
  int index = 1;
  for (int round = 0; round < 5; ++round) {
    ASSERT_OK_AND_ASSIGN(auto prep, client->BeginPreparation());
    ASSERT_OK_AND_ASSIGN(auto material, generator.Generate(prep));
    if (round) {
      EXPECT_NE(material.ciphertexts(0).SerializeAsString(), previous_ct);
      EXPECT_NE(material.galois_key(0).SerializeAsString(), previous_gk);
    }
    previous_ct = material.ciphertexts(0).SerializeAsString();
    previous_gk = material.galois_key(0).SerializeAsString();
    ASSERT_OK_AND_ASSIGN(auto installed, server->Install(material));
    ASSERT_OK(client->AcceptReady(MakeReceipt(material), installed));
    // Index is selected after provisioning, including the previous result.
    ASSERT_OK_AND_ASSIGN(auto query, client->GenerateQuery(prep.material_id(), index));
    EXPECT_LT(query.ByteSizeLong(), material.ByteSizeLong());
    ASSERT_OK_AND_ASSIGN(auto response, server->Handle(query));
    ASSERT_OK_AND_ASSIGN(auto record, client->Recover(response));
    ASSERT_OK_AND_ASSIGN(auto expected, server->ExpectedRecord(index));
    EXPECT_EQ(record, expected);
    index = static_cast<unsigned char>(record[0]) % 64;
    EXPECT_EQ(*client->GetState(prep.material_id()), State::kDone);
    EXPECT_FALSE(client->GenerateQuery(prep.material_id(), index).ok());
    ASSERT_OK(server->Release(prep.material_id()));
    EXPECT_FALSE(server->Install(material).ok());
    EXPECT_EQ(server->PublicParams().SerializeAsString(), pub.SerializeAsString());
  }
}

TEST(LocalMaterial, DomainSeparatedSecretsAndValidation) {
  Preparation prep;
  prep.set_config_id(std::string(32, 'c'));
  prep.set_material_id(std::string(32, 'i'));
  prep.set_secret_seed(std::string(32, 's'));
  ASSERT_OK_AND_ASSIGN(auto s, DeriveSeed(prep, "LWE-secret", rlwe::PRNG_TYPE_HKDF));
  ASSERT_OK_AND_ASSIGN(auto v, DeriveSeed(prep, "RLWE-secret", rlwe::PRNG_TYPE_HKDF));
  EXPECT_NE(s, v);
  EXPECT_EQ(s, *DeriveSeed(prep, "LWE-secret", rlwe::PRNG_TYPE_HKDF));
  prep.set_material_id(std::string(32, 'j'));
  EXPECT_NE(s, *DeriveSeed(prep, "LWE-secret", rlwe::PRNG_TYPE_HKDF));
  EXPECT_NE(v, *DeriveSeed(prep, "RLWE-secret", rlwe::PRNG_TYPE_HKDF));
  prep.set_secret_seed("short");
  EXPECT_FALSE(DeriveSeed(prep, "LWE-secret", rlwe::PRNG_TYPE_HKDF).ok());
  auto params = DemoParameters();
  params.lwe_plaintext_bit_size = 16;
  EXPECT_FALSE(ValidateParameters(params).ok());
  params = DemoParameters();
  params.lwe_error_variance = 4;
  EXPECT_FALSE(ValidateParameters(params).ok());
  params = DemoParameters();
  params.lwe_secret_dim = 1024;  // Old two-prime CRT worst-case range is too small.
  EXPECT_FALSE(ValidateParameters(params).ok());
}

TEST(LocalMaterial, PendingMismatchAbandonAndExactRetry) {
  const auto params = DemoParameters();
  ASSERT_OK_AND_ASSIGN(auto server, PreparedServer::Create(params));
  const auto pub = server->PublicParams();
  ASSERT_OK_AND_ASSIGN(auto client, PreparedClient::Create(params, pub));
  LocalMaterialGenerator generator(params, MakeGeneratorConfig(params, pub));
  ASSERT_OK_AND_ASSIGN(auto prep, client->BeginPreparation());
  EXPECT_FALSE(client->GenerateQuery(prep.material_id(), 2).ok());
  ASSERT_OK_AND_ASSIGN(auto material, generator.Generate(prep));
  ASSERT_OK_AND_ASSIGN(auto installed, server->Install(material));
  EXPECT_FALSE(server->Install(material).ok());
  ASSERT_OK(client->AcceptReady(MakeReceipt(material), installed));
  EXPECT_FALSE(client->GenerateQuery(prep.material_id(), 64).ok());
  ASSERT_OK_AND_ASSIGN(auto query, client->GenerateQuery(prep.material_id(), 2));
  EXPECT_FALSE(client->GenerateQuery(prep.material_id(), 3).ok());
  ASSERT_OK_AND_ASSIGN(auto retry, client->Retry(prep.material_id()));
  EXPECT_EQ(query.SerializeAsString(), retry.SerializeAsString());
  ASSERT_OK_AND_ASSIGN(auto response, server->Handle(query));
  ASSERT_OK_AND_ASSIGN(auto duplicate_response, server->Handle(retry));
  EXPECT_EQ(response.SerializeAsString(), duplicate_response.SerializeAsString());
  auto changed = query;
  changed.mutable_lwe_query()->set_b_coeffs(0, query.lwe_query().b_coeffs(0) + 1);
  EXPECT_FALSE(server->Handle(changed).ok());
  changed = query;
  changed.set_request_id(std::string(32, 'x'));
  EXPECT_FALSE(server->Handle(changed).ok());
  ASSERT_OK(client->Abandon(prep.material_id()));
  EXPECT_FALSE(client->Recover(response).ok());
  EXPECT_FALSE(client->Retry(prep.material_id()).ok());
  ASSERT_OK(server->Release(prep.material_id()));
  EXPECT_FALSE(server->Handle(query).ok());

  ASSERT_OK_AND_ASSIGN(auto prep2, client->BeginPreparation());
  ASSERT_OK_AND_ASSIGN(auto mat2, generator.Generate(prep2));
  auto wrong = MakeReceipt(mat2);
  wrong.set_material_digest(std::string(32, '!'));
  EXPECT_FALSE(client->AcceptReady(MakeReceipt(mat2), wrong).ok());
  EXPECT_EQ(*client->GetState(prep2.material_id()), State::kInvalid);
}

TEST(LocalMaterial, ConcurrentConsumptionAndReplay) {
  auto params = DemoParameters();
  params.prng_type = rlwe::PRNG_TYPE_CHACHA;
  params.linpir_params.prng_type = rlwe::PRNG_TYPE_CHACHA;
  ASSERT_OK_AND_ASSIGN(auto server, PreparedServer::Create(params));
  auto pub = server->PublicParams();
  ASSERT_OK_AND_ASSIGN(auto client, PreparedClient::Create(params, pub));
  LocalMaterialGenerator generator(params, MakeGeneratorConfig(params, pub));
  ASSERT_OK_AND_ASSIGN(auto prep, client->BeginPreparation());
  ASSERT_OK_AND_ASSIGN(auto mat, generator.Generate(prep));
  ASSERT_OK_AND_ASSIGN(auto ack, server->Install(mat));
  ASSERT_OK(client->AcceptReady(MakeReceipt(mat), ack));
  absl::StatusOr<Query> a = absl::UnknownError("not run"), b = a;
  std::thread first([&] { a = client->GenerateQuery(prep.material_id(), 1); });
  std::thread second([&] { b = client->GenerateQuery(prep.material_id(), 2); });
  first.join(); second.join();
  ASSERT_EQ(a.ok() + b.ok(), 1);
  const Query query = a.ok() ? *a : *b;
  absl::StatusOr<Response> r1 = absl::UnknownError("not run"), r2 = r1;
  std::thread s1([&] { r1 = server->Handle(query); });
  std::thread s2([&] { r2 = server->Handle(query); });
  s1.join(); s2.join();
  ASSERT_OK(r1);
  ASSERT_OK(r2);
  EXPECT_EQ(r1->SerializeAsString(), r2->SerializeAsString());
  ASSERT_OK_AND_ASSIGN(auto record, client->Recover(*r1));
  ASSERT_OK_AND_ASSIGN(auto expected, server->ExpectedRecord(a.ok() ? 1 : 2));
  EXPECT_EQ(record, expected);
}

TEST(LocalMaterial, RefreshAndRestartRejectOldMaterials) {
  const auto params = DemoParameters();
  ASSERT_OK_AND_ASSIGN(auto server, PreparedServer::Create(params));
  auto pub = server->PublicParams();
  ASSERT_OK_AND_ASSIGN(auto client, PreparedClient::Create(params, pub));
  LocalMaterialGenerator generator(params, MakeGeneratorConfig(params, pub));
  ASSERT_OK_AND_ASSIGN(auto prep, client->BeginPreparation());
  ASSERT_OK_AND_ASSIGN(auto mat, generator.Generate(prep));
  ASSERT_OK_AND_ASSIGN(auto ack, server->Install(mat));
  ASSERT_OK(client->AcceptReady(MakeReceipt(mat), ack));
  ASSERT_OK_AND_ASSIGN(auto query, client->GenerateQuery(prep.material_id(), 1));
  ASSERT_OK(server->Refresh());
  EXPECT_FALSE(server->Handle(query).ok());
  EXPECT_FALSE(server->Install(mat).ok());
  EXPECT_NE(ConfigurationId(params, pub), ConfigurationId(params, server->PublicParams()));
  ASSERT_OK_AND_ASSIGN(auto new_client, PreparedClient::Create(params, pub));
  EXPECT_FALSE(new_client->Retry(prep.material_id()).ok());
  EXPECT_FALSE(new_client->GenerateQuery(prep.material_id(), 1).ok());
}

TEST(LocalMaterial, WrongResponseBurnsMaterial) {
  const auto params = DemoParameters();
  ASSERT_OK_AND_ASSIGN(auto server, PreparedServer::Create(params));
  auto pub = server->PublicParams();
  ASSERT_OK_AND_ASSIGN(auto client, PreparedClient::Create(params, pub));
  LocalMaterialGenerator generator(params, MakeGeneratorConfig(params, pub));
  ASSERT_OK_AND_ASSIGN(auto prep, client->BeginPreparation());
  ASSERT_OK_AND_ASSIGN(auto mat, generator.Generate(prep));
  ASSERT_OK_AND_ASSIGN(auto ack, server->Install(mat));
  ASSERT_OK(client->AcceptReady(MakeReceipt(mat), ack));
  ASSERT_OK_AND_ASSIGN(auto query, client->GenerateQuery(prep.material_id(), 63));
  ASSERT_OK_AND_ASSIGN(auto response, server->Handle(query));
  auto wrong = response;
  wrong.set_request_id(std::string(32, 'x'));
  EXPECT_FALSE(client->Recover(wrong).ok());
  EXPECT_EQ(*client->GetState(prep.material_id()), State::kInvalid);
  EXPECT_FALSE(client->Recover(response).ok());
}
TEST(LocalMaterial, MalformedMaterialAndResponseAreRejected) {
  const auto params = DemoParameters();
  ASSERT_OK_AND_ASSIGN(auto server, PreparedServer::Create(params));
  auto pub = server->PublicParams();
  ASSERT_OK_AND_ASSIGN(auto client, PreparedClient::Create(params, pub));
  LocalMaterialGenerator generator(params, MakeGeneratorConfig(params, pub));
  ASSERT_OK_AND_ASSIGN(auto prep, client->BeginPreparation());
  auto bad_prep = prep;
  bad_prep.set_config_id(std::string(32, 'x'));
  EXPECT_FALSE(generator.Generate(bad_prep).ok());
  ASSERT_OK_AND_ASSIGN(auto mat, generator.Generate(prep));
  auto broken = mat;
  broken.mutable_ciphertexts(0)->clear_coeff_vectors();
  EXPECT_FALSE(server->Install(broken).ok());
  ASSERT_OK_AND_ASSIGN(auto ack, server->Install(mat));
  ASSERT_OK(client->AcceptReady(MakeReceipt(mat), ack));
  ASSERT_OK_AND_ASSIGN(auto query, client->GenerateQuery(prep.material_id(), 0));
  ASSERT_OK_AND_ASSIGN(auto response, server->Handle(query));
  response.mutable_pir_response()->mutable_linpir_responses(0)->clear_ct_inner_products();
  EXPECT_FALSE(client->Recover(response).ok());
  EXPECT_EQ(*client->GetState(prep.material_id()), State::kInvalid);
}

TEST(LocalMaterial, SeparateClientsShareStaticConfiguration) {
  const auto params = DemoParameters();
  ASSERT_OK_AND_ASSIGN(auto server, PreparedServer::Create(params));
  auto pub = server->PublicParams();
  ASSERT_OK_AND_ASSIGN(auto c1, PreparedClient::Create(params, pub));
  ASSERT_OK_AND_ASSIGN(auto c2, PreparedClient::Create(params, pub));
  LocalMaterialGenerator generator(params, MakeGeneratorConfig(params, pub));
  ASSERT_OK_AND_ASSIGN(auto p1, c1->BeginPreparation());
  ASSERT_OK_AND_ASSIGN(auto p2, c2->BeginPreparation());
  ASSERT_OK_AND_ASSIGN(auto m1, generator.Generate(p1));
  ASSERT_OK_AND_ASSIGN(auto m2, generator.Generate(p2));
  ASSERT_OK_AND_ASSIGN(auto a1, server->Install(m1));
  ASSERT_OK_AND_ASSIGN(auto a2, server->Install(m2));
  ASSERT_OK(c1->AcceptReady(MakeReceipt(m1), a1));
  ASSERT_OK(c2->AcceptReady(MakeReceipt(m2), a2));
  ASSERT_OK_AND_ASSIGN(auto q1, c1->GenerateQuery(p1.material_id(), 7));
  ASSERT_OK_AND_ASSIGN(auto q2, c2->GenerateQuery(p2.material_id(), 63));
  absl::StatusOr<Response> r1 = absl::UnknownError("not run"), r2 = r1;
  std::thread first([&] { r1 = server->Handle(q1); });
  std::thread second([&] { r2 = server->Handle(q2); });
  first.join(); second.join();
  ASSERT_OK(r1);
  ASSERT_OK(r2);
  ASSERT_OK_AND_ASSIGN(auto record1, c1->Recover(*r1));
  ASSERT_OK_AND_ASSIGN(auto record2, c2->Recover(*r2));
  ASSERT_OK_AND_ASSIGN(auto expected1, server->ExpectedRecord(7));
  ASSERT_OK_AND_ASSIGN(auto expected2, server->ExpectedRecord(63));
  EXPECT_EQ(record1, expected1);
  EXPECT_EQ(record2, expected2);
  EXPECT_EQ(pub.SerializeAsString(), server->PublicParams().SerializeAsString());
}
}  // namespace
}  // namespace hintless_pir::local_material
