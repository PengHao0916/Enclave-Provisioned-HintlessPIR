// Fixed-profile adaptation of Google shell-encryption's BFV/RNS algorithms.
// Copyright 2017, 2023, 2024 Google LLC (adapted algorithms).
// Licensed under the Apache License, Version 2.0:
// https://www.apache.org/licenses/LICENSE-2.0
// Distributed on an AS IS BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND.
// This portability implementation requires independent crypto/side-channel
// review; interoperability tests do not establish a security proof.

#include "rlwe_material.h"
#include "cng_primitives.h"
#include <intrin.h>

namespace hintless_vbs {
namespace {
ULONG BitReverse(ULONG value) {
  ULONG reversed = 0;
  for (ULONG i = 0; i < 12; ++i) { reversed = (reversed << 1) | (value & 1); value >>= 1; }
  return reversed;
}

// Montgomery R=2^64, matching upstream MontgomeryInt<Uint64>. All allowed
// moduli are below 2^46, so additions and the reduction high word cannot wrap.
struct Modulus {
  uint64_t q;
  uint64_t negative_inverse;
  uint64_t r_squared;
  uint64_t one;
  uint64_t Mul(uint64_t a, uint64_t b) const {
    uint64_t high = 0, correction_high = 0;
    const uint64_t low = _umul128(a, b, &high);
    const uint64_t m = low * negative_inverse;
    const uint64_t correction_low = _umul128(m, q, &correction_high);
    const uint64_t sum_low = low + correction_low;
    const uint64_t reduced = high + correction_high + static_cast<uint64_t>(sum_low < low);
    return reduced - (q & (0ULL - static_cast<uint64_t>(reduced >= q)));
  }
  uint64_t Add(uint64_t a, uint64_t b) const {
    const uint64_t sum = a + b;
    return sum - (q & (0ULL - static_cast<uint64_t>(sum >= q)));
  }
  uint64_t Sub(uint64_t a, uint64_t b) const { return Add(a, q - b); }
  uint64_t Import(uint64_t a) const { return Mul(a, r_squared); }
  uint64_t Export(uint64_t a) const { return Mul(a, 1); }
  uint64_t FromSigned32(uint32_t value) const {
    const int64_t signed_value = static_cast<int32_t>(value);
    const uint64_t negative = 0ULL - static_cast<uint64_t>(signed_value < 0);
    return Import(static_cast<uint64_t>(signed_value) + (q & negative));
  }
  uint64_t Pow(uint64_t a, uint64_t exponent) const {
    // Exponents are public modulus/root parameters only.
    uint64_t result = one;
    while (exponent) {
      if (exponent & 1) result = Mul(result, a);
      a = Mul(a, a); exponent >>= 1;
    }
    return result;
  }
  void Initialize(uint64_t modulus) {
    q = modulus;
    uint64_t inverse = 1;
    for (int i = 0; i < 6; ++i) inverse *= 2 - q * inverse;
    negative_inverse = 0ULL - inverse;
    uint64_t power = 1;
    for (int i = 0; i < 128; ++i) power = Add(power, power);
    r_squared = power;
    one = Import(1);
  }
};

struct Ntt {
  Modulus mod;
  uint64_t roots[kRingDegree];
  uint64_t inverse_roots[kRingDegree];
  uint64_t inverse_n;
  void Initialize(uint64_t q) {
    mod.Initialize(q);
    uint64_t psi = 0;
    for (uint64_t candidate = 2; candidate < q; ++candidate) {
      psi = mod.Pow(mod.Import(candidate), (q - 1) / (2 * kRingDegree));
      if (mod.Pow(psi, kRingDegree) != mod.one) break;
    }
    const uint64_t inverse_psi = mod.Pow(psi, q - 2);
    uint64_t forward = mod.one, backward = mod.one;
    for (ULONG i = 0; i < kRingDegree; ++i) {
      roots[BitReverse(i)] = forward;
      inverse_roots[BitReverse(i)] = backward;
      forward = mod.Mul(forward, psi);
      backward = mod.Mul(backward, inverse_psi);
    }
    inverse_n = mod.Pow(mod.Import(kRingDegree), q - 2);
  }
  void Forward(uint64_t* values) const {
    ULONG root = 1;
    for (ULONG half = kRingDegree / 2; half; half /= 2) {
      for (ULONG start = 0; start < kRingDegree; start += 2 * half) {
        const uint64_t factor = roots[root++];
        for (ULONG j = 0; j < half; ++j) {
          const uint64_t a = values[start + j];
          const uint64_t b = mod.Mul(values[start + j + half], factor);
          values[start + j] = mod.Add(a, b);
          values[start + j + half] = mod.Sub(a, b);
        }
      }
    }
  }
  void Inverse(uint64_t* values) const {
    for (ULONG half = 1; half < kRingDegree; half *= 2) {
      ULONG root = kRingDegree / (2 * half);
      for (ULONG start = 0; start < kRingDegree; start += 2 * half) {
        const uint64_t factor = inverse_roots[root++];
        for (ULONG j = 0; j < half; ++j) {
          const uint64_t a = values[start + j], b = values[start + j + half];
          values[start + j] = mod.Add(a, b);
          values[start + j + half] = mod.Mul(mod.Sub(a, b), factor);
        }
      }
    }
    for (ULONG i = 0; i < kRingDegree; ++i) values[i] = mod.Mul(values[i], inverse_n);
  }
};

struct Workspace {
  Ntt qs[2];
  Ntt ts[3];
  uint32_t lwe[2048];
  uint32_t coefficients[kRingDegree];
  uint64_t secret[2][kRingDegree];
  uint64_t source[2][kRingDegree];
  uint64_t slots[kRingDegree];
  uint64_t encoded[2][kRingDegree];
  uint64_t pad[2][kRingDegree];
  uint64_t error[2][kRingDegree];
};
struct SecureWorkspace {
  Workspace* value = static_cast<Workspace*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(Workspace)));
  ~SecureWorkspace() {
    if (value) { SecureZeroMemory(value, sizeof(Workspace)); HeapFree(GetProcessHeap(), 0, value); }
  }
};
struct Seeds {
  BYTE lwe[64]{}, rlwe[64]{}, noise[64]{};
  ~Seeds() { SecureZeroMemory(this, sizeof(*this)); }
};
struct OutputGuard {
  RawMaterial* out;
  bool success = false;
  ~OutputGuard() { if (!success) SecureZeroMemory(out, sizeof(*out)); }
};

HRESULT FreshNoise(HkdfPrng& prng, BYTE seed[64]) {
  NTSTATUS status = BCryptGenRandom(nullptr, seed, 64, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if (status < 0) { SecureZeroMemory(seed, 64); return HRESULT_FROM_NT(status); }
  HRESULT hr = prng.Initialize(seed);
  SecureZeroMemory(seed, 64);
  return hr;
}
void CoefficientToRns(const Workspace& w, const uint32_t* coeffs, uint64_t values[2][kRingDegree]) {
  for (ULONG q = 0; q < 2; ++q) {
    for (ULONG i = 0; i < kRingDegree; ++i) values[q][i] = w.qs[q].mod.FromSigned32(coeffs[i]);
    w.qs[q].Forward(values[q]);
  }
}
HRESULT UniformPad(HkdfPrng& prng, const Workspace& w, uint64_t pad[2][kRingDegree]) {
  constexpr uint64_t mask = (1ULL << 45) - 1;
  for (ULONG q = 0; q < 2; ++q) {
    for (ULONG i = 0; i < kRingDegree; ++i) {
      uint64_t value = 0;
      do {
        HRESULT hr = prng.Rand64(&value);
        if (FAILED(hr)) return hr;
        value &= mask;
      } while (value >= w.qs[q].mod.q);
      // Upstream ImportRandom uses the sampled value directly as Montgomery.
      pad[q][i] = value;
    }
  }
  return S_OK;
}
void Encode(Workspace& w, ULONG limb, ULONG dimension, ULONG rows_per_block) {
  const auto& ntt_t = w.ts[limb];
  const auto& mt = ntt_t.mod;
  SecureZeroMemory(w.slots, sizeof(w.slots));
  ULONG power = 1;
  for (ULONG i = 0; i < kRingDegree / 2; ++i) {
    if (i < dimension) w.slots[BitReverse((power - 1) / 2)] = mt.FromSigned32(w.lwe[i]);
    const ULONG second = (rows_per_block / 2 + i) % (kRingDegree / 2);
    const ULONG co_power = (power * (2 * kRingDegree - 1)) % (2 * kRingDegree);
    if (second < dimension) w.slots[BitReverse((co_power - 1) / 2)] = mt.FromSigned32(w.lwe[second]);
    power = power * 5 % (2 * kRingDegree);
  }
  ntt_t.Inverse(w.slots);
  const uint64_t q_residue = ((kCiphertextModuli[0] % mt.q) * (kCiphertextModuli[1] % mt.q)) % mt.q;
  const uint64_t negative_q = mt.Sub(0, mt.Import(q_residue));
  for (ULONG i = 0; i < kRingDegree; ++i) w.slots[i] = mt.Export(mt.Mul(w.slots[i], negative_q));
  for (ULONG q = 0; q < 2; ++q) {
    const auto& mq = w.qs[q].mod;
    const uint64_t inverse_t = mq.Pow(mq.Import(mt.q), mq.q - 2);
    for (ULONG i = 0; i < kRingDegree; ++i) w.encoded[q][i] = mq.Mul(mq.Import(w.slots[i]), inverse_t);
    w.qs[q].Forward(w.encoded[q]);
  }
}
}  // namespace

HRESULT GenerateMaterial(const MaterialConfig& config, const BYTE material_id[32],
                          const BYTE master_seed[32], RawMaterial* output) {
  if (!material_id || !master_seed || !output) return E_INVALIDARG;
  SecureZeroMemory(output, sizeof(*output));
  OutputGuard guard{output};
  ULONG limbs = 0, dimension = 0, rows = 0;
  const uint64_t* plaintext_moduli = nullptr;
  switch (config.profile) {
    case MaterialProfile::kFunctional:
      limbs = 2; dimension = 32; rows = 8;
      plaintext_moduli = kFunctionalPlaintextModuli;
      break;
    case MaterialProfile::kEightMiB:
      limbs = 2; dimension = 1024; rows = 1024;
      plaintext_moduli = kEightMiBPlaintextModuli;
      break;
    default: return E_INVALIDARG;
  }
  SecureWorkspace allocation;
  if (!allocation.value) return E_OUTOFMEMORY;
  auto& w = *allocation.value;
  for (ULONG q = 0; q < 2; ++q) w.qs[q].Initialize(kCiphertextModuli[q]);
  for (ULONG t = 0; t < limbs; ++t) w.ts[t].Initialize(plaintext_moduli[t]);
  Seeds seeds;
  HkdfPrng key_prng, pad_prng, noise_prng;
#define TRY_HR(expression) do { HRESULT hr = (expression); if (FAILED(hr)) return hr; } while (false)
  TRY_HR(DeriveMaterialSeed(master_seed, config.configuration_id, material_id, false, seeds.lwe));
  TRY_HR(DeriveMaterialSeed(master_seed, config.configuration_id, material_id, true, seeds.rlwe));
  TRY_HR(key_prng.Initialize(seeds.lwe));
  TRY_HR(SampleLweTernary(key_prng, dimension, w.lwe));
  TRY_HR(key_prng.Initialize(seeds.rlwe));
  TRY_HR(SampleRlweVariance8(key_prng, kRingDegree, w.coefficients));
  CoefficientToRns(w, w.coefficients, w.secret);
  for (ULONG q = 0; q < 2; ++q) {
    for (ULONG j = 0; j < kRingDegree; ++j)
      w.source[q][BitReverse(j)] = w.secret[q][BitReverse((2 + 5 * j) % kRingDegree)];
  }
  for (ULONG t = 0; t < limbs; ++t) {
    Encode(w, t, dimension, rows);
    TRY_HR(pad_prng.Initialize(config.ciphertext_pad_seeds[t]));
    TRY_HR(UniformPad(pad_prng, w, w.pad));
    TRY_HR(FreshNoise(noise_prng, seeds.noise));
    TRY_HR(SampleRlweVariance8(noise_prng, kRingDegree, w.coefficients));
    CoefficientToRns(w, w.coefficients, w.error);
    for (ULONG q = 0; q < 2; ++q) {
      const auto& mod = w.qs[q].mod;
      for (ULONG i = 0; i < kRingDegree; ++i) {
        const uint64_t b = mod.Add(mod.Add(w.error[q][i], w.encoded[q][i]),
                                   mod.Mul(w.pad[q][i], w.secret[q][i]));
        output->ciphertext_b[t][q][i] = mod.Export(b);
      }
    }
  }
  TRY_HR(pad_prng.Initialize(config.galois_pad_seed));
  TRY_HR(FreshNoise(noise_prng, seeds.noise));
  for (ULONG row = 0; row < kGaloisRows; ++row) {
    TRY_HR(UniformPad(pad_prng, w, w.pad));
    TRY_HR(SampleRlweVariance8(noise_prng, kRingDegree, w.coefficients));
    CoefficientToRns(w, w.coefficients, w.error);
    for (ULONG q = 0; q < 2; ++q) {
      const auto& mod = w.qs[q].mod;
      const uint64_t gadget = row / 3 == q ? mod.Import(1ULL << (16 * (row % 3))) : 0;
      for (ULONG i = 0; i < kRingDegree; ++i) {
        const uint64_t b = mod.Sub(mod.Add(w.error[q][i], mod.Mul(gadget, w.source[q][i])),
                                   mod.Mul(w.pad[q][i], w.secret[q][i]));
        output->galois_b[row][q][i] = mod.Export(b);
      }
    }
  }
#undef TRY_HR
  output->version = 1;
  output->plaintext_limbs = limbs;
  CopyMemory(output->configuration_id, config.configuration_id, 32);
  CopyMemory(output->material_id, material_id, 32);
  guard.success = true;
  return S_OK;
}
}  // namespace hintless_vbs
