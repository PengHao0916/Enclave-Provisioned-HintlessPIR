// Deterministic PUBLIC test inputs. Never use these values for real materials.
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "absl/status/statusor.h"
#include "local_material/protocol.h"
#include "lwe/sample_error.h"
#include "openssl/sha.h"
#include "shell_encryption/montgomery.h"
#include "shell_encryption/prng/single_thread_hkdf_prng.h"
#include "shell_encryption/sample_error.h"

template <typename T> T Take(absl::StatusOr<T> result) {
  if (!result.ok()) { std::cerr << result.status() << '\n'; std::exit(1); }
  return std::move(result).value();
}
std::string Hex(const std::string& input) {
  std::ostringstream out;
  for (unsigned char c : input) out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
  return out.str();
}
std::string Hash(const std::string& input) {
  std::string output(32, '\0');
  SHA256(reinterpret_cast<const uint8_t*>(input.data()), input.size(),
         reinterpret_cast<uint8_t*>(output.data()));
  return Hex(output);
}
void Word(std::string& bytes, uint32_t value) {
  for (int j = 0; j < 4; ++j) bytes.push_back(static_cast<char>(value >> (8 * j)));
}
int main() {
  namespace lm = hintless_pir::local_material;
  using Mod = rlwe::MontgomeryInt<rlwe::Uint64>;
  constexpr rlwe::Uint64 q = 35184371884033;
  auto mod = Take(Mod::Params::Create(q));
  const int dimensions[] = {1, 7, 8, 9, 32, 1408, 2048, 65536};
  std::cout << "{\"schema\":1,\"source\":\"pinned-linux-upstream-public-test-fixtures\",\"vectors\":[\n";
  for (int c = 0; c < 8; ++c) {
    lm::Preparation prep;
    std::string master(32, '\0'), config(32, '\0'), material(32, '\0');
    for (int i = 0; i < 32; ++i) {
      master[i] = static_cast<char>(i + 17 * c);
      config[i] = static_cast<char>(i + 71 + 13 * c);
      material[i] = static_cast<char>(255 - i - 19 * c);
    }
    prep.set_secret_seed(master); prep.set_config_id(config); prep.set_material_id(material);
    auto lwe_seed = Take(lm::DeriveSeed(prep, "LWE-secret", rlwe::PRNG_TYPE_HKDF));
    auto rlwe_seed = Take(lm::DeriveSeed(prep, "RLWE-secret", rlwe::PRNG_TYPE_HKDF));
    auto p = Take(rlwe::SingleThreadHkdfPrng::Create(lwe_seed));
    std::string stream;
    for (int i = 0; i < 20000; ++i) stream.push_back(Take(p->Rand8()));
    p = Take(rlwe::SingleThreadHkdfPrng::Create(lwe_seed));
    for (int i = 0; i < 8157; ++i) Take(p->Rand8());
    uint64_t word = Take(p->Rand64());
    std::string word_bytes;
    for (int i = 0; i < 8; ++i) word_bytes.push_back(static_cast<char>(word >> (8 * i)));
    p = Take(rlwe::SingleThreadHkdfPrng::Create(lwe_seed));
    auto lwe = Take(hintless_pir::lwe::SampleUniformTernary(dimensions[c], p.get()));
    std::string lwe_bytes;
    for (int i = 0; i < lwe.size(); ++i) Word(lwe_bytes, lwe[i]);
    p = Take(rlwe::SingleThreadHkdfPrng::Create(rlwe_seed));
    auto rlwe = Take(rlwe::SampleFromErrorDistribution<Mod>(4096, 8, p.get(), mod.get()));
    std::string rlwe_bytes;
    for (auto coefficient : rlwe) {
      auto value = coefficient.ExportInt(mod.get());
      int64_t signed_value = value <= q / 2 ? value : -static_cast<int64_t>(q - value);
      Word(rlwe_bytes, static_cast<uint32_t>(signed_value));
    }
    if (c) std::cout << ",\n";
    std::cout << "{\"case\":" << c << ",\"lwe_dimension\":" << dimensions[c]
      << ",\"lwe_seed\":\"" << Hex(lwe_seed) << "\",\"rlwe_seed\":\"" << Hex(rlwe_seed)
      << "\",\"stream_sha256\":\"" << Hash(stream) << "\",\"boundary_rand64_le\":\"" << Hex(word_bytes)
      << "\",\"lwe_sha256\":\"" << Hash(lwe_bytes) << "\",\"rlwe_coeff_sha256\":\"" << Hash(rlwe_bytes) << "\"}";
  }
  std::cout << "\n]}\n";
}
