#ifndef HINTLESS_VBS_RLWE_MATERIAL_H_
#define HINTLESS_VBS_RLWE_MATERIAL_H_
#include <stdint.h>
#ifdef _WIN32
#include <windows.h>
#else
using BYTE = uint8_t;
using ULONG = uint32_t;
using HRESULT = int32_t;
#endif

namespace hintless_vbs {
constexpr ULONG kRingDegree = 4096;
constexpr ULONG kRnsLimbs = 2;
constexpr ULONG kGaloisRows = 6;
constexpr uint64_t kCiphertextModuli[2] = {35184371884033ULL, 35184371703809ULL};
constexpr uint64_t kFunctionalPlaintextModuli[2] = {2056193, 1990657};
constexpr uint64_t kEightMiBPlaintextModuli[2] = {2236417, 2277377};
enum class MaterialProfile : ULONG { kFunctional = 1, kEightMiB = 2 };

// Public configuration only. Numeric parameters are fixed by an allowlisted
// profile so untrusted callers cannot substitute weakened crypto parameters.
struct MaterialConfig {
  MaterialProfile profile;
  BYTE configuration_id[32];
  BYTE ciphertext_pad_seeds[3][64];
  BYTE galois_pad_seed[64];
};
struct RawMaterial {
  ULONG version;
  ULONG plaintext_limbs;
  BYTE configuration_id[32];
  BYTE material_id[32];
  // Canonical (not Montgomery) coefficients, in upstream NTT order.
  uint64_t ciphertext_b[3][kRnsLimbs][kRingDegree];
  uint64_t galois_b[kGaloisRows][kRnsLimbs][kRingDegree];
};
static_assert(sizeof(MaterialConfig) == 292, "Unexpected public config layout");
static_assert(sizeof(RawMaterial) == 589896, "Unexpected public material layout");

// TRUSTED-memory API, not an exported enclave function. An enclave deployment
// must obtain master_seed from an attested private channel, never host plaintext.
// All encryption/key-switch noise is sampled internally with BCryptGenRandom.
HRESULT GenerateMaterial(const MaterialConfig& config, const BYTE material_id[32],
                          const BYTE master_seed[32], RawMaterial* output);
}  // namespace hintless_vbs
#endif
