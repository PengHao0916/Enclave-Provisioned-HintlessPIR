// Sampling/PRNG compatibility follows Google HintlessPIR and shell-encryption.
// Copyright 2021, 2023, 2024 Google LLC (adapted sampling algorithms).
// Licensed under the Apache License, Version 2.0:
// https://www.apache.org/licenses/LICENSE-2.0
// Distributed on an AS IS BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND.

#include "cng_primitives.h"

namespace hintless_vbs {
namespace {
class Algorithm {
 public:
  BCRYPT_ALG_HANDLE value = nullptr;
  ~Algorithm() { if (value) BCryptCloseAlgorithmProvider(value, 0); }
};
class Hash {
 public:
  BCRYPT_HASH_HANDLE value = nullptr;
  ~Hash() { if (value) BCryptDestroyHash(value); }
};
HRESULT Status(NTSTATUS status) {
  return status < 0 ? HRESULT_FROM_NT(status) : S_OK;
}
bool ValidBytes(const BYTE* bytes, ULONG size) { return size == 0 || bytes; }
HRESULT Hmac(BCRYPT_ALG_HANDLE alg, const BYTE* key, ULONG key_size,
             const BYTE* a, ULONG a_size, const BYTE* b, ULONG b_size,
             const BYTE* c, ULONG c_size, BYTE output[32]) {
  Hash hash;
  NTSTATUS s = BCryptCreateHash(alg, &hash.value, nullptr, 0,
                                const_cast<BYTE*>(key), key_size, 0);
  if (s >= 0 && a_size) s = BCryptHashData(hash.value, const_cast<BYTE*>(a), a_size, 0);
  if (s >= 0 && b_size) s = BCryptHashData(hash.value, const_cast<BYTE*>(b), b_size, 0);
  if (s >= 0 && c_size) s = BCryptHashData(hash.value, const_cast<BYTE*>(c), c_size, 0);
  if (s >= 0) s = BCryptFinishHash(hash.value, output, 32, 0);
  return Status(s);
}
void AppendField(BYTE* output, ULONG& offset, const BYTE* field, ULONG length) {
  const uint64_t wide_length = length;
  for (int i = 7; i >= 0; --i)
    output[offset++] = static_cast<BYTE>(wide_length >> (8 * i));
  CopyMemory(output + offset, field, length);
  offset += length;
}
int Popcount8(BYTE input) {
  // Fixed number of operations; no secret-indexed lookup table.
  unsigned value = input;
  value -= (value >> 1) & 0x55;
  value = (value & 0x33) + ((value >> 2) & 0x33);
  return static_cast<int>((value + (value >> 4)) & 0x0f);
}
}  // namespace

HRESULT Sha256(const BYTE* bytes, ULONG size, BYTE output[32]) {
  if (!ValidBytes(bytes, size) || !output) return E_INVALIDARG;
  Algorithm alg;
  NTSTATUS s = BCryptOpenAlgorithmProvider(&alg.value, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
  if (s >= 0) s = BCryptHash(alg.value, nullptr, 0, const_cast<BYTE*>(bytes),
                            size, output, 32);
  if (s < 0) SecureZeroMemory(output, 32);
  return Status(s);
}

HRESULT HkdfSha256(const BYTE* ikm, ULONG ikm_size,
                   const BYTE* salt, ULONG salt_size,
                   const BYTE* info, ULONG info_size,
                   BYTE* output, ULONG output_size) {
  if (!ValidBytes(ikm, ikm_size) || !ValidBytes(salt, salt_size) ||
      !ValidBytes(info, info_size) || !ValidBytes(output, output_size) ||
      output_size > kHkdfBlockBytes) return E_INVALIDARG;
  if (!output_size) return S_OK;
  Algorithm alg;
  NTSTATUS s = BCryptOpenAlgorithmProvider(&alg.value, BCRYPT_SHA256_ALGORITHM,
                                           nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
  if (s < 0) { SecureZeroMemory(output, output_size); return Status(s); }
  BYTE zero_salt[32]{};
  BYTE prk[32]{};
  BYTE block[32]{};
  if (!salt_size) { salt = zero_salt; salt_size = sizeof(zero_salt); }
  HRESULT hr = Hmac(alg.value, salt, salt_size, ikm, ikm_size,
                    nullptr, 0, nullptr, 0, prk);
  ULONG completed = 0;
  ULONG previous_size = 0;
  for (ULONG i = 1; SUCCEEDED(hr) && completed < output_size; ++i) {
    BYTE index = static_cast<BYTE>(i);
    hr = Hmac(alg.value, prk, sizeof(prk), block, previous_size,
              info, info_size, &index, 1, block);
    if (FAILED(hr)) break;
    ULONG take = output_size - completed;
    if (take > sizeof(block)) take = sizeof(block);
    CopyMemory(output + completed, block, take);
    completed += take;
    previous_size = sizeof(block);
  }
  SecureZeroMemory(prk, sizeof(prk));
  SecureZeroMemory(block, sizeof(block));
  if (FAILED(hr)) SecureZeroMemory(output, output_size);
  return hr;
}

HRESULT DeriveMaterialSeed(const BYTE master[32], const BYTE config[32],
                           const BYTE material[32], bool rlwe,
                           BYTE output[kSeedBytes]) {
  if (!master || !config || !material || !output) return E_INVALIDARG;
  constexpr char domain[] = "hintless/local-material/v1";
  constexpr char lwe_role[] = "LWE-secret";
  constexpr char rlwe_role[] = "RLWE-secret";
  BYTE info[128]{};
  ULONG offset = 0;
  AppendField(info, offset, reinterpret_cast<const BYTE*>(domain), sizeof(domain) - 1);
  AppendField(info, offset, material, 32);
  AppendField(info, offset, reinterpret_cast<const BYTE*>(rlwe ? rlwe_role : lwe_role),
              rlwe ? sizeof(rlwe_role) - 1 : sizeof(lwe_role) - 1);
  HRESULT hr = HkdfSha256(master, 32, config, 32, info, offset, output, kSeedBytes);
  SecureZeroMemory(info, sizeof(info));
  return hr;
}

HkdfPrng::~HkdfPrng() { Reset(); }
void HkdfPrng::Reset() {
  SecureZeroMemory(key_, sizeof(key_));
  SecureZeroMemory(buffer_, sizeof(buffer_));
  position_ = kHkdfBlockBytes;
  counter_ = 0;
  ready_ = false;
}
HRESULT HkdfPrng::Initialize(const BYTE seed[kSeedBytes]) {
  Reset();
  if (!seed) return E_INVALIDARG;
  CopyMemory(key_, seed, sizeof(key_));
  ready_ = true;
  HRESULT hr = Refill();
  if (FAILED(hr)) Reset();
  return hr;
}
HRESULT HkdfPrng::Refill() {
  if (!ready_ || counter_ >= 0x7fffffffU) return E_UNEXPECTED;
  BYTE salt[16]{'s', 'a', 'l', 't'};
  BYTE digits[10]{};
  ULONG number = counter_, length = 0;
  do { digits[length++] = static_cast<BYTE>('0' + number % 10); number /= 10; } while (number);
  for (ULONG i = 0; i < length; ++i) salt[4 + i] = digits[length - i - 1];
  HRESULT hr = HkdfSha256(key_, sizeof(key_), salt, 4 + length,
                          nullptr, 0, buffer_, sizeof(buffer_));
  if (FAILED(hr)) { Reset(); return hr; }
  ++counter_;
  position_ = 0;
  return S_OK;
}
HRESULT HkdfPrng::Rand8(BYTE* value) {
  if (!value) return E_INVALIDARG;
  *value = 0;
  if (!ready_) return E_UNEXPECTED;
  if (position_ == kHkdfBlockBytes) {
    HRESULT hr = Refill();
    if (FAILED(hr)) return hr;
  }
  *value = buffer_[position_++];
  return S_OK;
}
HRESULT HkdfPrng::Rand64(uint64_t* value) {
  if (!value) return E_INVALIDARG;
  *value = 0;
  for (int i = 0; i < 8; ++i) {
    BYTE b = 0;
    HRESULT hr = Rand8(&b);
    if (FAILED(hr)) { *value = 0; return hr; }
    *value |= static_cast<uint64_t>(b) << (8 * i);
  }
  return S_OK;
}
HRESULT HkdfPrng::Read(BYTE* output, ULONG size) {
  if (!ValidBytes(output, size)) return E_INVALIDARG;
  for (ULONG i = 0; i < size; ++i) {
    HRESULT hr = Rand8(output + i);
    if (FAILED(hr)) { SecureZeroMemory(output, size); return hr; }
  }
  return S_OK;
}

HRESULT SampleLweTernary(HkdfPrng& prng, ULONG count, uint32_t* coefficients) {
  if (!coefficients || !count || count > 65536) return E_INVALIDARG;
  ULONG filled = 0;
  while (filled < count) {
    const ULONG batch = count - filled < 8 ? count - filled : 8;
    BYTE missing = static_cast<BYTE>((1U << batch) - 1);
    BYTE bits0 = 0, bits1 = 0;
    while (missing) {
      BYTE r0 = 0, r1 = 0;
      HRESULT hr = prng.Rand8(&r0);
      if (SUCCEEDED(hr)) hr = prng.Rand8(&r1);
      if (FAILED(hr)) { SecureZeroMemory(coefficients, count * sizeof(uint32_t)); return hr; }
      bits0 ^= r0 & missing;
      bits1 ^= r1 & missing;
      missing = static_cast<BYTE>(~bits0 & bits1);
    }
    for (ULONG i = 0; i < batch; ++i) {
      const uint32_t a = (bits0 >> i) & 1;
      const uint32_t b = (bits1 >> i) & 1;
      coefficients[filled++] = ((0U - (a & (b ^ 1U))) & 1U) | (0U - (a & b));
    }
  }
  return S_OK;
}

HRESULT SampleRlweVariance8(HkdfPrng& prng, ULONG count, uint32_t* coefficients) {
  if (!coefficients || !count || count > 65536) return E_INVALIDARG;
  for (ULONG i = 0; i < count; ++i) {
    BYTE bytes[4]{};
    HRESULT hr = prng.Read(bytes, sizeof(bytes));
    if (FAILED(hr)) { SecureZeroMemory(coefficients, count * sizeof(uint32_t)); return hr; }
    const int value = Popcount8(bytes[0]) - Popcount8(bytes[1]) +
        Popcount8(bytes[2]) - Popcount8(bytes[3]);
    coefficients[i] = static_cast<uint32_t>(value);
    SecureZeroMemory(bytes, sizeof(bytes));
  }
  return S_OK;
}
}  // namespace hintless_vbs
