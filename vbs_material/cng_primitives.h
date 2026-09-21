#ifndef HINTLESS_VBS_CNG_PRIMITIVES_H_
#define HINTLESS_VBS_CNG_PRIMITIVES_H_
#include <windows.h>
#include <bcrypt.h>
#include <stdint.h>

namespace hintless_vbs {
constexpr ULONG kSeedBytes = 64;  // shell-encryption HKDF PRNG seed length.
constexpr ULONG kHkdfBlockBytes = 255 * 32;

HRESULT Sha256(const BYTE* bytes, ULONG size, BYTE output[32]);
// Bounded RFC 5869 SHA-256 HKDF. No platform calls outside enclave CNG APIs.
HRESULT HkdfSha256(const BYTE* ikm, ULONG ikm_size,
                   const BYTE* salt, ULONG salt_size,
                   const BYTE* info, ULONG info_size,
                   BYTE* output, ULONG output_size);
HRESULT DeriveMaterialSeed(const BYTE master[32], const BYTE config[32],
                           const BYTE material[32], bool rlwe,
                           BYTE output[kSeedBytes]);

// Byte-for-byte compatibility with the pinned upstream SingleThreadHkdfPrng:
// HKDF(seed, salt="salt" + decimal counter, info="", length=8160), LE Rand64.
// Not copyable: avoid inadvertent copies of secret key/PRNG state.
class HkdfPrng final {
 public:
  HkdfPrng() = default;
  ~HkdfPrng();
  HkdfPrng(const HkdfPrng&) = delete;
  HkdfPrng& operator=(const HkdfPrng&) = delete;
  HRESULT Initialize(const BYTE seed[kSeedBytes]);
  HRESULT Rand8(BYTE* value);
  HRESULT Rand64(uint64_t* value);
  HRESULT Read(BYTE* output, ULONG size);
  void Reset();
 private:
  HRESULT Refill();
  BYTE key_[kSeedBytes]{};
  BYTE buffer_[kHkdfBlockBytes]{};
  ULONG position_ = kHkdfBlockBytes;
  ULONG counter_ = 0;
  bool ready_ = false;
};

// Internal trusted-memory APIs only, NOT exported enclave entry points.
HRESULT SampleLweTernary(HkdfPrng& prng, ULONG count, uint32_t* coefficients);
// Pinned functional/8 MiB profile uses RLWE centered-binomial variance 8.
// Output contains signed coefficients represented modulo 2^32; RNS/NTT
// conversion and encryption are implemented in rlwe_material.cc.
HRESULT SampleRlweVariance8(HkdfPrng& prng, ULONG count, uint32_t* coefficients);
}  // namespace hintless_vbs
#endif
