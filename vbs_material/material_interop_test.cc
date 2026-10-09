// Correctness harness only. Private-research modes use fresh client seeds and
// the real encrypted VBS path, but this process still owns both the synthetic
// client oracle and server; it is not a production network endpoint.
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "absl/status/statusor.h"
#include "hintless_simplepir/client.h"
#include "hintless_simplepir/utils.h"
#include "local_material/protocol.h"
#include "lwe/lwe_symmetric_encryption.h"
#include "shell_encryption/montgomery.h"
#include "shell_encryption/prng/single_thread_hkdf_prng.h"
#include "shell_encryption/rns/finite_field_encoder.h"
#include "shell_encryption/rns/rns_context.h"
#include "shell_encryption/rns/rns_gadget.h"
#include "shell_encryption/rns/rns_polynomial.h"
#include "shell_encryption/rns/rns_secret_key.h"
#include "vbs_material/material_test_abi.h"
#include "vbs_material/client_journal.h"
#include "vbs_material/lifecycle_test_driver.h"

namespace lm = hintless_pir::local_material;
namespace native = hintless_vbs;
namespace vbs = hintless_pir::vbs;
using Mod = rlwe::MontgomeryInt<rlwe::Uint64>;
using Context = rlwe::RnsContext<Mod>;
using Poly = rlwe::RnsPolynomial<Mod>;

[[noreturn]] void Fail(const std::string& message) { std::cerr << message << '\n'; std::exit(1); }
template <typename T> T Take(absl::StatusOr<T> value) {
  if (!value.ok()) Fail(value.status().ToString());
  return std::move(value).value();
}
void Check(absl::Status status) { if (!status.ok()) Fail(status.ToString()); }
void Wipe(void* value, size_t size) {
  volatile unsigned char* bytes = static_cast<volatile unsigned char*>(value);
  while (size--) *bytes++ = 0;
}
uint64_t ElapsedNs(std::chrono::steady_clock::time_point start) {
  return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
      std::chrono::steady_clock::now() - start).count());
}
std::string Hex(const std::string& value) {
  std::ostringstream out;
  for (unsigned char c : value) out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
  return out.str();
}
std::string WindowsPath(std::string path) {
  if (path.size() < 7 || path.substr(0, 5) != "/mnt/" || path[6] != '/')
    Fail("Interop output paths must be absolute /mnt/<drive>/ paths.");
  path = std::string(1, path[5]) + ":" + path.substr(6);
  std::replace(path.begin(), path.end(), '/', '\\');
  return path;
}
template <typename T> void Write(const std::string& path, const T& object) {
  std::ofstream file(path, std::ios::binary);
  file.write(reinterpret_cast<const char*>(&object), sizeof(object));
  if (!file) Fail("Writing public interop fixture failed.");
}
template <typename T> void Read(const std::string& path, T& object) {
  std::ifstream file(path, std::ios::binary);
  file.read(reinterpret_cast<char*>(&object), sizeof(object));
  if (!file || file.peek() != EOF) Fail("Unexpected raw material file size.");
}
void Run(const std::string& program, bool enclave, const std::string& dll,
         const std::string& input, const std::string& output, const std::string& log) {
  auto win_input = WindowsPath(input), win_output = WindowsPath(output);
  pid_t pid = fork();
  if (pid < 0) Fail("Cannot launch Windows test backend.");
  if (pid == 0) {
    if (!freopen(log.c_str(), "w", stdout)) _exit(127);
    if (enclave) execl(program.c_str(), program.c_str(), "--enclave", dll.c_str(), win_input.c_str(), win_output.c_str(), nullptr);
    else execl(program.c_str(), program.c_str(), "--native", win_input.c_str(), win_output.c_str(), nullptr);
    _exit(127);
  }
  int status = 0;
  if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
    Fail("Windows material test failed; inspect " + log);
}

rlwe::SerializedRnsPolynomial Serialize(const uint64_t values[2][4096], const Context& context) {
  auto moduli = context.MainPrimeModuli();
  std::vector<std::vector<Mod>> vectors(2);
  for (int q = 0; q < 2; ++q) {
    vectors[q].reserve(4096);
    for (int i = 0; i < 4096; ++i) {
      if (values[q][i] >= native::kCiphertextModuli[q]) Fail("Non-canonical raw coefficient.");
      vectors[q].push_back(Take(Mod::ImportInt(values[q][i], moduli[q]->ModParams())));
    }
  }
  return Take(Take(Poly::Create(std::move(vectors), true)).Serialize(moduli));
}

void VerifyNoise(Poly noise, const Context& context) {
  auto moduli = context.MainPrimeModuli();
  Check(noise.ConvertToCoeffForm(moduli));
  bool nonzero = false;
  for (int i = 0; i < 4096; ++i) {
    int64_t first = 0;
    for (int q = 0; q < 2; ++q) {
      auto modulus = moduli[q]->ModParams()->modulus;
      auto v = noise.Coeffs()[q][i].ExportInt(moduli[q]->ModParams());
      int64_t centered = v <= modulus / 2 ? v : -static_cast<int64_t>(modulus - v);
      if (centered < -16 || centered > 16) Fail("Material violates the original RLWE noise relation.");
      if (q == 0) first = centered;
      else if (centered != first) Fail("Noise differs between RNS limbs.");
      nonzero |= centered != 0;
    }
  }
  if (!nonzero) Fail("Unexpected all-zero encryption noise.");
}

void VerifyAllMaterialRelations(const lm::Parameters& params, const lm::GeneratorConfig& config,
                                const lm::Material& material, const std::string& lwe_seed,
                                const std::string& rlwe_seed) {
  auto lwe_prng = Take(rlwe::SingleThreadHkdfPrng::Create(lwe_seed));
  auto lwe = Take(hintless_pir::lwe::SymmetricLweKey::Sample(params.lwe_secret_dim, lwe_prng.get()));
  for (int t = 0; t < material.ciphertexts_size(); ++t) {
    auto context = Take(Context::CreateForBfvFiniteFieldEncoding(12, params.linpir_params.qs, {}, params.linpir_params.ts[t]));
    auto moduli = context.MainPrimeModuli();
    auto encoder = Take(rlwe::FiniteFieldEncoder<Mod>::Create(&context));
    auto sk_prng = Take(rlwe::SingleThreadHkdfPrng::Create(rlwe_seed));
    auto sk = Take(rlwe::RnsRlweSecretKey<Mod>::Sample(12, 8, moduli, sk_prng.get()));
    std::vector<rlwe::Uint64> values(2048, 0), slots(4096, 0);
    for (int i = 0; i < params.lwe_secret_dim; ++i) {
      values[i] = hintless_pir::hintless_simplepir::ConvertModulus<rlwe::Uint64>(
          lwe.Key()[i], rlwe::Uint64{1} << 32, params.linpir_params.ts[t], rlwe::Uint64{1} << 31);
    }
    for (int i = 0; i < 2048; ++i) {
      slots[i] = values[i];
      slots[2048 + i] = values[(params.linpir_params.rows_per_block / 2 + i) % 2048];
    }
    auto plain = Take(encoder.EncodeBfv(slots, moduli));
    auto pad_prng = Take(rlwe::SingleThreadHkdfPrng::Create(config.ciphertext_pad_seeds(t)));
    auto pad = Take(Poly::SampleUniform(12, pad_prng.get(), moduli));
    Check(pad.MulInPlace(sk.Key(), moduli));
    auto b = Take(Poly::Deserialize(material.ciphertexts(t), moduli));
    Check(b.SubInPlace(plain, moduli));
    Check(b.SubInPlace(pad, moduli));
    VerifyNoise(std::move(b), context);
    if (t != 0) continue;
    auto hats = Take(context.MainPrimeModulusComplements(1));
    auto inverses = Take(context.MainPrimeModulusCrtFactors(1));
    auto gadget = Take(rlwe::RnsGadget<Mod>::Create(12, {16,16}, hats, inverses, moduli));
    auto source = Take(sk.Key().Substitute(5, moduli));
    auto gk_prng = Take(rlwe::SingleThreadHkdfPrng::Create(config.galois_pad_seed()));
    for (int r = 0; r < 6; ++r) {
      auto gk_pad = Take(Poly::SampleUniform(12, gk_prng.get(), moduli));
      Check(gk_pad.MulInPlace(sk.Key(), moduli));
      auto target = source;
      Check(target.MulInPlace(gadget.Component(r), moduli));
      auto key_b = Take(Poly::Deserialize(material.galois_key(r), moduli));
      Check(key_b.AddInPlace(gk_pad, moduli));
      Check(key_b.SubInPlace(target, moduli));
      VerifyNoise(std::move(key_b), context);
    }
  }
}

int main(int argc, char** argv) {
  if (argc < 5 || argc > 6) {
    std::cerr << "Usage: material_interop_test native|enclave|native-lifecycle|enclave-lifecycle|native-private-lifecycle|enclave-private-lifecycle functional|8mb|512mb|2gb|8gb WINDOWS_EXE OUTPUT_DIR [WINDOWS_DLL_PATH]\n";
    return 2;
  }
  const std::string mode = argv[1];
  const bool private_lifecycle = mode == "native-private-lifecycle" ||
                                 mode == "enclave-private-lifecycle";
  const bool lifecycle = mode == "native-lifecycle" || mode == "enclave-lifecycle" ||
                         private_lifecycle;
  const bool enclave = mode == "enclave" || mode == "enclave-lifecycle" ||
                       mode == "enclave-private-lifecycle";
  if ((!enclave && mode != "native" && mode != "native-lifecycle" &&
       mode != "native-private-lifecycle") || (enclave && argc != 6)) return 2;
  signal(SIGPIPE, SIG_IGN);
  const std::string profile = argv[2], program = argv[3], output_dir = argv[4];
  WindowsPath(output_dir + "/check");
  std::filesystem::create_directories(output_dir);
  auto params = Take(lm::ParametersForProfile(profile));
  const auto setup_start = std::chrono::steady_clock::now();
  auto server = Take(lm::PreparedServer::Create(params));
  const uint64_t server_setup_ns = ElapsedNs(setup_start);
  std::unique_ptr<vbs::AuthenticatedInstaller> installer;
  std::unique_ptr<vbs::ClientJournal> journal;
  std::string journal_directory;
  if (lifecycle) {
    installer = Take(vbs::AuthenticatedInstaller::Create(params, server.get()));
    char directory[] = "/tmp/hintless-interop-journal-XXXXXX";
    if (!mkdtemp(directory)) Fail("Cannot create private journal test directory.");
    journal_directory = directory;
    journal = Take(vbs::ClientJournal::Open(journal_directory + "/client.log"));
  }
  auto pub = server->PublicParams();
  uint64_t static_rlwe_component_bytes = 0;
  for (const auto& hint : pub.linpir_response_hints())
    static_rlwe_component_bytes += hint.ByteSizeLong();
  auto config = lm::MakeGeneratorConfig(params, pub);
  auto context = Take(Context::CreateForBfvFiniteFieldEncoding(12, params.linpir_params.qs, {}, params.linpir_params.ts[0]));
  const int64_t indices[] = {0, params.db_rows * params.db_cols - 1,
                             (params.db_rows / 2) * params.db_cols + params.db_cols / 2};
  std::vector<std::string> records;
  std::vector<std::string> completed_material_ids;
  for (uint32_t c = 0; c < 3; ++c) {
    native::PublicMaterialTestRequest request{};
    request.version = 1; request.size = sizeof(request); request.case_index = c;
    request.config.profile = profile == "functional" ? native::MaterialProfile::kFunctional : native::MaterialProfile::kEightMiB;
    if (config.config_id().size() != 32 || config.galois_pad_seed().size() != 64) Fail("Unexpected configuration lengths.");
    memcpy(request.config.configuration_id, config.config_id().data(), 32);
    memcpy(request.config.galois_pad_seed, config.galois_pad_seed().data(), 64);
    for (int i = 0; i < config.ciphertext_pad_seeds_size(); ++i) {
      if (config.ciphertext_pad_seeds(i).size() != 64) Fail("Unexpected public seed length.");
      memcpy(request.config.ciphertext_pad_seeds[i], config.ciphertext_pad_seeds(i).data(), 64);
    }
    const std::string base = output_dir + "/" + profile + "-" + std::to_string(c);
    BYTE master[32]{}, id[32]{}, challenge[32]{};
    native::PrivateResearchMaterialRequest private_request{};
    if (private_lifecycle) {
      auto random_master = Take(lm::RandomId());
      auto random_id = Take(lm::RandomId());
      auto random_challenge = Take(lm::RandomId());
      if (random_master.size() != 32 || random_id.size() != 32 || random_challenge.size() != 32)
        Fail("Unexpected random identifier length.");
      memcpy(master, random_master.data(), 32);
      memcpy(id, random_id.data(), 32);
      memcpy(challenge, random_challenge.data(), 32);
      private_request.version = 1; private_request.size = sizeof(private_request);
      private_request.config = request.config;
      memcpy(private_request.material_id, id, 32);
      memcpy(private_request.master_seed, master, 32);
      memcpy(private_request.challenge, challenge, 32);
      Wipe(random_master.data(), random_master.size());
      Wipe(random_id.data(), random_id.size());
      Wipe(random_challenge.data(), random_challenge.size());
    } else {
      native::PublicTestSecrets(c, master, id);
    }
    const std::string material_id(reinterpret_cast<char*>(id), 32);
    if (std::find(completed_material_ids.begin(), completed_material_ids.end(), material_id) !=
        completed_material_ids.end()) Fail("Random material identifier repeated within one run.");
    completed_material_ids.push_back(material_id);
    if (!private_lifecycle) Write(base + ".request.bin", request);
    auto raw = std::make_unique<native::RawMaterial>();
    native::PrivateResearchLifecycleMetrics lifecycle_metrics{};
    if (lifecycle) {
      Check(journal->Begin(config.config_id(), material_id));
      if (private_lifecycle) {
        Check(vbs::RunPrivateResearchLifecycle(program, enclave ? argv[5] : "",
            base + ".backend.log", private_request, *installer, *raw, lifecycle_metrics));
        Wipe(private_request.master_seed, sizeof(private_request.master_seed));
      } else {
        Check(vbs::RunPublicLifecycle(program, enclave ? argv[5] : "",
            base + ".backend.log", request, *installer, *raw));
      }
      Check(journal->Ready(material_id));
      Write(base + ".material.bin", *raw);
      if (!private_lifecycle && c == 0) for (int corrupt = 1; corrupt <= 4; ++corrupt) {
        auto rejected = request; rejected.case_index = 10 + corrupt;
        auto unused = std::make_unique<native::RawMaterial>();
        Check(vbs::RunPublicLifecycle(program, enclave ? argv[5] : "", base + ".reject-" + std::to_string(corrupt) + ".log",
            rejected, *installer, *unused, corrupt));
        Check(server->Release(std::string(reinterpret_cast<char*>(unused->material_id), 32)));
      }
    } else {
      Run(program, enclave, enclave ? argv[5] : "", base + ".request.bin", base + ".material.bin", base + ".backend.json");
      Read(base + ".material.bin", *raw);
    }
    if (raw->version != 1 || raw->plaintext_limbs != params.linpir_params.ts.size() ||
        memcmp(raw->configuration_id, config.config_id().data(), 32) || memcmp(raw->material_id, id, 32))
      Fail("Raw material binding mismatch.");
    lm::Material material;
    material.set_config_id(config.config_id());
    material.set_material_id(id, 32);
    for (unsigned t = 0; t < raw->plaintext_limbs; ++t) *material.add_ciphertexts() = Serialize(raw->ciphertext_b[t], context);
    for (unsigned r = 0; r < 6; ++r) *material.add_galois_key() = Serialize(raw->galois_b[r], context);
    if (!lifecycle) Take(server->Install(material));
    lm::Preparation prep;
    prep.set_config_id(config.config_id()); prep.set_material_id(id, 32); prep.set_secret_seed(master, 32);
    auto lwe_seed = Take(lm::DeriveSeed(prep, "LWE-secret", rlwe::PRNG_TYPE_HKDF));
    auto rlwe_seed = Take(lm::DeriveSeed(prep, "RLWE-secret", rlwe::PRNG_TYPE_HKDF));
    VerifyAllMaterialRelations(params, config, material, lwe_seed, rlwe_seed);
    auto client = Take(hintless_pir::hintless_simplepir::Client::CreateForPreparedMaterial(params, pub, Hex(prep.material_id()), rlwe_seed));
    if (lifecycle) Check(journal->Reserve(material_id));
    const auto online_start = std::chrono::steady_clock::now();
    auto stage_start = online_start;
    auto low = Take(client->GeneratePreparedRequest(indices[c], lwe_seed));
    lm::Query query;
    query.set_config_id(config.config_id()); query.set_material_id(prep.material_id()); query.set_request_id(Take(lm::RandomId()));
    *query.mutable_lwe_query() = low.ct_query_vector();
    const uint64_t query_generation_ns = ElapsedNs(stage_start);
    if (lifecycle) Check(journal->Commit(material_id, query.SerializeAsString()));
    stage_start = std::chrono::steady_clock::now();
    auto response = Take(server->Handle(query));
    const uint64_t server_handle_ns = ElapsedNs(stage_start);
    stage_start = std::chrono::steady_clock::now();
    auto record = Take(client->RecoverRecord(response.pir_response()));
    const uint64_t recovery_ns = ElapsedNs(stage_start);
    const uint64_t online_total_ns = ElapsedNs(online_start);
    if (record != Take(server->ExpectedRecord(indices[c]))) Fail("Recovered record differs from original database, case " + std::to_string(c));
    auto retry_query = query;
    if (lifecycle && (!retry_query.ParseFromString(Take(journal->Retry(material_id))) ||
        retry_query.SerializeAsString() != query.SerializeAsString())) Fail("Durable retry changed.");
    if (Take(server->Handle(retry_query)).SerializeAsString() != response.SerializeAsString()) Fail("Exact retry changed.");
    auto changed = query; changed.set_request_id(Take(lm::RandomId()));
    if (server->Handle(changed).ok()) Fail("Material accepted a different logical request.");
    Check(server->Release(prep.material_id()));
    if (server->Handle(query).ok()) Fail("Released material accepted another query.");
    if (lifecycle) {
      Check(journal->Finish(material_id));
      if (journal->Retry(material_id).ok() || journal->Reserve(material_id).ok()) Fail("Finished journal material reused.");
    }
    uint64_t online_rlwe_component_bytes = 0;
    for (const auto& limb : response.pir_response().linpir_responses())
      online_rlwe_component_bytes += limb.ByteSizeLong();
    std::string case_record = "{\"case\":" + std::to_string(c) + ",\"index\":" + std::to_string(indices[c]) +
        ",\"record_correct\":true,\"all_rlwe_noise_relations_checked\":true,\"retry_checked\":true,\"reuse_rejected\":true,\"material_payload_bytes\":" + std::to_string(material.ByteSizeLong()) +
        ",\"online_query_bytes\":" + std::to_string(query.ByteSizeLong()) +
        ",\"online_response_bytes\":" + std::to_string(response.ByteSizeLong()) +
        ",\"online_rlwe_component_bytes\":" + std::to_string(online_rlwe_component_bytes);
    case_record += ",\"query_generation_ns\":" + std::to_string(query_generation_ns) +
        ",\"server_handle_ns\":" + std::to_string(server_handle_ns) +
        ",\"recovery_ns\":" + std::to_string(recovery_ns) +
        ",\"online_total_ns\":" + std::to_string(online_total_ns);
    if (private_lifecycle) {
      case_record += ",\"enclave_load_ns\":" + std::to_string(lifecycle_metrics.enclave_load_ns) +
          ",\"channel_begin_ns\":" + std::to_string(lifecycle_metrics.channel_begin_ns) +
          ",\"client_seal_ns\":" + std::to_string(lifecycle_metrics.client_seal_ns) +
          ",\"enclave_generate_ns\":" + std::to_string(lifecycle_metrics.enclave_generate_ns) +
          ",\"receipt_accept_ns\":" + std::to_string(lifecycle_metrics.receipt_accept_ns) +
          ",\"installation_roundtrip_ns\":" + std::to_string(lifecycle_metrics.installation_roundtrip_ns) +
          ",\"material_lifecycle_total_ns\":" + std::to_string(lifecycle_metrics.total_ns);
    }
    case_record += "}";
    records.push_back(std::move(case_record));
    Wipe(master, sizeof(master));
    Wipe(challenge, sizeof(challenge));
  }
  if (lifecycle) {
    journal.reset();
    journal = Take(vbs::ClientJournal::Open(journal_directory + "/client.log"));
    for (const auto& material_id : completed_material_ids) {
      if (Take(journal->State(material_id)) != vbs::DurableState::kDone)
        Fail("Journal restart lost terminal tombstone.");
    }
    journal.reset();
    // Only this newly created private test directory is removed.
    std::filesystem::remove_all(journal_directory);
  }
  const char* backend = private_lifecycle ?
      (enclave ? "vbs-enclave-private-seed-research" : "windows-native-private-seed-research-NOT-TEE") :
      (enclave ? "vbs-enclave-public-material-test" : "windows-native-material-NOT-TEE");
  std::ostringstream result;
  result << "{\"backend\":\"" << backend
            << "\",\"real_attestation_verified\":false,\"authenticated_installation_and_journal\":" << (lifecycle ? "true" : "false")
            << ",\"installation_negative_cases\":" << ((lifecycle && !private_lifecycle) ? 4 : 0)
            << ",\"public_test_secrets_only\":" << (private_lifecycle ? "false" : "true")
            << ",\"private_seed_channel_executed\":" << (private_lifecycle ? "true" : "false")
            << ",\"attestation_scope\":\"" << (enclave ? "local-report-binding-only" : "public-fixture-no-platform-trust") << "\""
            << ",\"client_server_process_isolation\":false"
            << ",\"profile\":\"" << profile << "\",\"database_bytes\":"
            << params.db_rows * params.db_cols * params.db_record_bit_size / 8
            << ",\"server_setup_ns\":" << server_setup_ns
            << ",\"public_setup_bytes\":" << pub.ByteSizeLong()
            << ",\"static_rlwe_component_bytes\":" << static_rlwe_component_bytes
            << ",\"correct_queries\":3,\"cases\":[";
  for (size_t i = 0; i < records.size(); ++i) result << (i ? "," : "") << records[i];
  result << "]}\n";
  std::ofstream result_file(output_dir + "/result.json", std::ios::binary);
  result_file << result.str();
  if (!result_file) Fail("Writing experiment result failed.");
  std::cout << result.str();
}
