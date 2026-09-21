#include "crypto_self_test.h"
#include "cng_primitives.h"
#include "test_vectors.h"

namespace hintless_vbs {
namespace {
bool EqualsHex(const BYTE* bytes, ULONG count, const char* hex) {
  constexpr char alphabet[] = "0123456789abcdef";
  for (ULONG i = 0; i < count; ++i) {
    if (hex[2 * i] != alphabet[bytes[i] >> 4] ||
        hex[2 * i + 1] != alphabet[bytes[i] & 15]) return false;
  }
  return hex[count * 2] == '\0';
}
class Buffer {
 public:
  explicit Buffer(SIZE_T size) : size_(size) {
    data = static_cast<BYTE*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size));
  }
  ~Buffer() {
    if (data) { SecureZeroMemory(data, size_); HeapFree(GetProcessHeap(), 0, data); }
  }
  BYTE* data = nullptr;
 private:
  SIZE_T size_;
};
}  // namespace

HRESULT CryptoSelfTest(ULONG* checks_passed) {
  if (!checks_passed) return E_INVALIDARG;
  *checks_passed = 0;
#define VERIFY(condition) do { if (!(condition)) return E_FAIL; ++*checks_passed; } while (false)
  // RFC 5869 Appendix A.1 and A.3, independent of the Linux oracle.
  BYTE ikm[22], salt[13], info[10], output[64]{};
  FillMemory(ikm, sizeof(ikm), 0x0b);
  for (ULONG i = 0; i < sizeof(salt); ++i) salt[i] = static_cast<BYTE>(i);
  for (ULONG i = 0; i < sizeof(info); ++i) info[i] = static_cast<BYTE>(0xf0 + i);
  VERIFY(SUCCEEDED(HkdfSha256(ikm, sizeof(ikm), salt, sizeof(salt), info, sizeof(info), output, 42)) &&
      EqualsHex(output, 42, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));
  VERIFY(SUCCEEDED(HkdfSha256(ikm, sizeof(ikm), nullptr, 0, nullptr, 0, output, 42)) &&
      EqualsHex(output, 42, "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"));
  VERIFY(HkdfSha256(ikm, sizeof(ikm), nullptr, 0, nullptr, 0, output, 8161) == E_INVALIDARG);
  VERIFY(HkdfSha256(nullptr, 1, nullptr, 0, nullptr, 0, output, 1) == E_INVALIDARG);
  VERIFY(HkdfSha256(ikm, sizeof(ikm), nullptr, 0, nullptr, 0, nullptr, 0) == S_OK);
  VERIFY(DeriveMaterialSeed(nullptr, salt, info, false, output) == E_INVALIDARG);

  Buffer stream(20000), coefficients(65536 * sizeof(uint32_t));
  if (!stream.data || !coefficients.data) return E_OUTOFMEMORY;
  auto* words = reinterpret_cast<uint32_t*>(coefficients.data);
  HkdfPrng prng;
  uint64_t boundary_word = 1;
  VERIFY(FAILED(prng.Rand64(&boundary_word)) && boundary_word == 0);
  BYTE lwe_seed[kSeedBytes]{}, rlwe_seed[kSeedBytes]{}, digest[32]{};
  for (ULONG c = 0; c < ARRAYSIZE(kUpstreamVectors); ++c) {
    const auto& expected = kUpstreamVectors[c];
    BYTE master[32], config[32], material[32];
    for (ULONG i = 0; i < 32; ++i) {
      master[i] = static_cast<BYTE>(i + 17 * c);
      config[i] = static_cast<BYTE>(i + 71 + 13 * c);
      material[i] = static_cast<BYTE>(255 - i - 19 * c);
    }
    VERIFY(SUCCEEDED(DeriveMaterialSeed(master, config, material, false, lwe_seed)) &&
        EqualsHex(lwe_seed, sizeof(lwe_seed), expected.lwe_seed));
    VERIFY(SUCCEEDED(DeriveMaterialSeed(master, config, material, true, rlwe_seed)) &&
        EqualsHex(rlwe_seed, sizeof(rlwe_seed), expected.rlwe_seed));
    VERIFY(SUCCEEDED(prng.Initialize(lwe_seed)) && SUCCEEDED(prng.Read(stream.data, 20000)) &&
        SUCCEEDED(Sha256(stream.data, 20000, digest)) && EqualsHex(digest, 32, expected.stream_hash));
    VERIFY(SUCCEEDED(prng.Initialize(lwe_seed)) && SUCCEEDED(prng.Read(stream.data, 8157)) &&
        SUCCEEDED(prng.Rand64(&boundary_word)) &&
        EqualsHex(reinterpret_cast<const BYTE*>(&boundary_word), 8, expected.boundary_word));
    VERIFY(SUCCEEDED(prng.Initialize(lwe_seed)) && SUCCEEDED(SampleLweTernary(prng, expected.dimension, words)) &&
        SUCCEEDED(Sha256(coefficients.data, expected.dimension * 4, digest)) && EqualsHex(digest, 32, expected.lwe_hash));
    VERIFY(SUCCEEDED(prng.Initialize(rlwe_seed)) && SUCCEEDED(SampleRlweVariance8(prng, 4096, words)) &&
        SUCCEEDED(Sha256(coefficients.data, 4096 * 4, digest)) && EqualsHex(digest, 32, expected.rlwe_hash));
  }
  VERIFY(SampleLweTernary(prng, 0, words) == E_INVALIDARG);
  VERIFY(SampleRlweVariance8(prng, 65537, words) == E_INVALIDARG);
  VERIFY(prng.Rand8(nullptr) == E_INVALIDARG);
  prng.Reset();
  BYTE value = 1;
  VERIFY(FAILED(prng.Rand8(&value)) && value == 0);
  SecureZeroMemory(lwe_seed, sizeof(lwe_seed));
  SecureZeroMemory(rlwe_seed, sizeof(rlwe_seed));
  return S_OK;
#undef VERIFY
}
}  // namespace hintless_vbs
