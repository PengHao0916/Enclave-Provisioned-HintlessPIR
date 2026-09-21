// Bounded RFC 9180 base-mode implementation using Windows CNG only.
// Independently checked against the RFC A.3.1 public test vector.
#include "hpke.h"
#include <string.h>
#include "hpke_test_vector.h"

namespace hintless_vbs {
namespace {
HRESULT Status(NTSTATUS s) { return s < 0 ? HRESULT_FROM_NT(s) : S_OK; }
struct Algorithm {
  BCRYPT_ALG_HANDLE h = nullptr;
  ~Algorithm() { if (h) BCryptCloseAlgorithmProvider(h, 0); }
};
struct Key {
  BCRYPT_KEY_HANDLE h = nullptr;
  ~Key() { if (h) BCryptDestroyKey(h); }
};
struct Agreement {
  BCRYPT_SECRET_HANDLE h = nullptr;
  ~Agreement() { if (h) BCryptDestroySecret(h); }
};
template <ULONG N> struct Secret {
  BYTE data[N]{};
  ~Secret() { SecureZeroMemory(data, N); }
};
constexpr BYTE kKemSuite[] = {'K','E','M',0,16};
constexpr BYTE kHpkeSuite[] = {'H','P','K','E',0,16,0,1,0,1};
// All outputs in this implementation are at most one SHA-256 block.
HRESULT Label(bool expand, bool kem, const BYTE* salt_or_prk, const char* label,
              const BYTE* input, ULONG size, BYTE* output, ULONG output_size) {
  if (size > 256 || (size && !input) || !output || output_size > 32 ||
      (expand && !salt_or_prk)) return E_INVALIDARG;
  Secret<512> buffer;
  ULONG n = 0;
  if (expand) { buffer.data[n++] = 0; buffer.data[n++] = static_cast<BYTE>(output_size); }
  CopyMemory(buffer.data + n, "HPKE-v1", 7); n += 7;
  const ULONG suite_size = kem ? sizeof(kKemSuite) : sizeof(kHpkeSuite);
  CopyMemory(buffer.data + n, kem ? kKemSuite : kHpkeSuite, suite_size); n += suite_size;
  const ULONG label_size = static_cast<ULONG>(strlen(label));
  if (label_size > 32) return E_INVALIDARG;
  CopyMemory(buffer.data + n, label, label_size); n += label_size;
  if (size) { CopyMemory(buffer.data + n, input, size); n += size; }
  if (expand) buffer.data[n++] = 1;
  Secret<32> zero, full;
  HRESULT hr = HmacSha256(salt_or_prk ? salt_or_prk : zero.data, buffer.data, n, full.data);
  if (SUCCEEDED(hr)) CopyMemory(output, full.data, output_size);
  else SecureZeroMemory(output, output_size);
  return hr;
}
HRESULT PublicBlob(const BYTE pub[65], BYTE blob[72]) {
  if (!pub || pub[0] != 4) return E_INVALIDARG;
  BCRYPT_ECCKEY_BLOB header{BCRYPT_ECDH_PUBLIC_P256_MAGIC, 32};
  CopyMemory(blob, &header, sizeof(header));
  CopyMemory(blob + sizeof(header), pub + 1, 64);
  return S_OK;
}
}  // namespace

bool ConstantTimeEqual(const BYTE* a, const BYTE* b, ULONG size) {
  if (!a || !b) return false;
  volatile BYTE difference = 0;
  for (ULONG i = 0; i < size; ++i) difference = static_cast<BYTE>(difference | (a[i] ^ b[i]));
  return difference == 0;
}
HRESULT HmacSha256(const BYTE key[32], const BYTE* input, ULONG size, BYTE out[32]) {
  if (!key || (size && !input) || !out) return E_INVALIDARG;
  Algorithm algorithm;
  NTSTATUS s = BCryptOpenAlgorithmProvider(&algorithm.h, BCRYPT_SHA256_ALGORITHM,
                                            nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
  if (s >= 0) s = BCryptHash(algorithm.h, const_cast<BYTE*>(key), 32,
                             const_cast<BYTE*>(input), size, out, 32);
  if (s < 0) SecureZeroMemory(out, 32);
  return Status(s);
}
P256Key::~P256Key() { Reset(); }
void P256Key::Reset() {
  if (key_) BCryptDestroyKey(key_);
  if (algorithm_) BCryptCloseAlgorithmProvider(algorithm_, 0);
  key_ = nullptr; algorithm_ = nullptr;
  SecureZeroMemory(public_key_, sizeof(public_key_));
}
HRESULT P256Key::Generate(BYTE public_key[65]) {
  Reset();
  if (!public_key) return E_INVALIDARG;
  SecureZeroMemory(public_key, 65);
  NTSTATUS s = BCryptOpenAlgorithmProvider(&algorithm_, BCRYPT_ECDH_P256_ALGORITHM, nullptr, 0);
  if (s >= 0) s = BCryptGenerateKeyPair(algorithm_, &key_, 256, 0);
  if (s >= 0) s = BCryptFinalizeKeyPair(key_, 0);
  BYTE blob[72]{};
  ULONG written = 0;
  if (s >= 0) s = BCryptExportKey(key_, nullptr, BCRYPT_ECCPUBLIC_BLOB,
                                  blob, sizeof(blob), &written, 0);
  if (s < 0 || written != sizeof(blob)) { Reset(); return s < 0 ? Status(s) : E_FAIL; }
  public_key_[0] = 4;
  CopyMemory(public_key_ + 1, blob + sizeof(BCRYPT_ECCKEY_BLOB), 64);
  CopyMemory(public_key, public_key_, 65);
  return S_OK;
}
HRESULT P256Key::ImportTestKey(const BYTE pub[65], const BYTE priv[32]) {
  Reset();
  if (!pub || !priv || pub[0] != 4) return E_INVALIDARG;
  Secret<104> blob;
  BCRYPT_ECCKEY_BLOB header{BCRYPT_ECDH_PRIVATE_P256_MAGIC, 32};
  CopyMemory(blob.data, &header, sizeof(header));
  CopyMemory(blob.data + sizeof(header), pub + 1, 64);
  CopyMemory(blob.data + sizeof(header) + 64, priv, 32);
  NTSTATUS s = BCryptOpenAlgorithmProvider(&algorithm_, BCRYPT_ECDH_P256_ALGORITHM, nullptr, 0);
  if (s >= 0) s = BCryptImportKeyPair(algorithm_, nullptr, BCRYPT_ECCPRIVATE_BLOB,
                                     &key_, blob.data, sizeof(blob.data), 0);
  if (s < 0) { Reset(); return Status(s); }
  CopyMemory(public_key_, pub, 65);
  return S_OK;
}

HpkeContext::~HpkeContext() { Reset(); }
void HpkeContext::Reset() {
  SecureZeroMemory(key_, sizeof(key_)); SecureZeroMemory(nonce_, sizeof(nonce_));
  SecureZeroMemory(exporter_, sizeof(exporter_));
  ready_ = false; sender_ = false; used_ = false;
}
HRESULT HpkeContext::SetupSender(const BYTE recipient[65], const BYTE* info,
                                ULONG size, BYTE enc[65]) {
  Reset();
  if (!enc) return E_INVALIDARG;
  P256Key ephemeral;
  HRESULT hr = ephemeral.Generate(enc);
  if (SUCCEEDED(hr)) hr = Setup(ephemeral, recipient, true, info, size);
  if (FAILED(hr)) SecureZeroMemory(enc, 65);
  return hr;
}
HRESULT HpkeContext::SetupReceiver(const P256Key& recipient, const BYTE enc[65],
                                  const BYTE* info, ULONG size) {
  return Setup(recipient, enc, false, info, size);
}
HRESULT HpkeContext::Setup(const P256Key& own, const BYTE peer[65], bool sender,
                          const BYTE* info, ULONG size) {
  Reset();
  if (!own.key_ || !peer || size > 256 || (size && !info)) return E_INVALIDARG;
  BYTE blob[72]{};
  HRESULT hr = PublicBlob(peer, blob);
  if (FAILED(hr)) return hr;
  Key imported;
  NTSTATUS s = BCryptImportKeyPair(own.algorithm_, nullptr, BCRYPT_ECCPUBLIC_BLOB,
                                    &imported.h, blob, sizeof(blob), 0);
  // CNG validates the point; never use BCRYPT_NO_KEY_VALIDATION.
  Agreement agreement;
  if (s >= 0) s = BCryptSecretAgreement(own.key_, imported.h, &agreement.h, 0);
  Secret<32> raw, dh, prk, shared, psk_hash, info_hash, secret;
  ULONG written = 0;
  if (s >= 0) s = BCryptDeriveKey(agreement.h, BCRYPT_KDF_RAW_SECRET, nullptr,
                                  raw.data, 32, &written, 0);
  if (s < 0 || written != 32) return s < 0 ? Status(s) : E_FAIL;
  // CNG raw ECDH is little endian; RFC 9180 P-256 DH is big endian.
  for (ULONG i = 0; i < 32; ++i) dh.data[i] = raw.data[31 - i];
  BYTE kem_context[130]{};
  CopyMemory(kem_context, sender ? own.public_key_ : peer, 65);
  CopyMemory(kem_context + 65, sender ? peer : own.public_key_, 65);
  hr = Label(false, true, nullptr, "eae_prk", dh.data, 32, prk.data, 32);
  if (SUCCEEDED(hr)) hr = Label(true, true, prk.data, "shared_secret", kem_context, 130, shared.data, 32);
  if (SUCCEEDED(hr)) hr = Label(false, false, nullptr, "psk_id_hash", nullptr, 0, psk_hash.data, 32);
  if (SUCCEEDED(hr)) hr = Label(false, false, nullptr, "info_hash", info, size, info_hash.data, 32);
  BYTE schedule[65]{};  // Mode 0, psk_id_hash, info_hash.
  CopyMemory(schedule + 1, psk_hash.data, 32); CopyMemory(schedule + 33, info_hash.data, 32);
  if (SUCCEEDED(hr)) hr = Label(false, false, shared.data, "secret", nullptr, 0, secret.data, 32);
  if (SUCCEEDED(hr)) hr = Label(true, false, secret.data, "key", schedule, 65, key_, 16);
  if (SUCCEEDED(hr)) hr = Label(true, false, secret.data, "base_nonce", schedule, 65, nonce_, 12);
  if (SUCCEEDED(hr)) hr = Label(true, false, secret.data, "exp", schedule, 65, exporter_, 32);
  if (FAILED(hr)) { Reset(); return hr; }
  ready_ = true; sender_ = sender;
  return S_OK;
}
HRESULT HpkeContext::Seal(const BYTE* aad, ULONG aad_size, const BYTE* pt, ULONG size, BYTE* ct) {
  return Aead(true, aad, aad_size, pt, size, ct);
}
HRESULT HpkeContext::Open(const BYTE* aad, ULONG aad_size, const BYTE* ct, ULONG size, BYTE* pt) {
  return Aead(false, aad, aad_size, ct, size, pt);
}
HRESULT HpkeContext::Aead(bool seal, const BYTE* aad, ULONG aad_size,
                         const BYTE* input, ULONG size, BYTE* output) {
  if (!input || !output || size > 272 || (!seal && size < 16) ||
      (seal && size > 256) || aad_size > 256 || (aad_size && !aad)) return E_INVALIDARG;
  const ULONG plain_size = seal ? size : size - 16;
  const ULONG out_size = seal ? size + 16 : plain_size;
  SecureZeroMemory(output, out_size);
  if (!ready_ || used_ || sender_ != seal) return E_UNEXPECTED;
  used_ = true;  // Failed opens also consume this context; no nonce reuse.
  Algorithm algorithm;
  Key key;
  NTSTATUS s = BCryptOpenAlgorithmProvider(&algorithm.h, BCRYPT_AES_ALGORITHM, nullptr, 0);
  if (s >= 0) s = BCryptSetProperty(algorithm.h, BCRYPT_CHAINING_MODE,
      reinterpret_cast<BYTE*>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)), sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
  if (s >= 0) s = BCryptGenerateSymmetricKey(algorithm.h, &key.h, nullptr, 0, key_, 16, 0);
  BYTE nonce[12], tag[16]{};
  CopyMemory(nonce, nonce_, 12);
  if (!seal) CopyMemory(tag, input + plain_size, 16);
  BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
  BCRYPT_INIT_AUTH_MODE_INFO(auth);
  auth.pbNonce = nonce; auth.cbNonce = 12;
  auth.pbAuthData = const_cast<BYTE*>(aad); auth.cbAuthData = aad_size;
  auth.pbTag = tag; auth.cbTag = 16;
  ULONG written = 0;
  if (s >= 0) {
    if (seal) s = BCryptEncrypt(key.h, const_cast<BYTE*>(input), plain_size, &auth,
                                nullptr, 0, output, plain_size, &written, 0);
    else s = BCryptDecrypt(key.h, const_cast<BYTE*>(input), plain_size, &auth,
                             nullptr, 0, output, plain_size, &written, 0);
  }
  if (s < 0 || written != plain_size) {
    SecureZeroMemory(output, out_size); return s < 0 ? Status(s) : E_FAIL;
  }
  if (seal) CopyMemory(output + plain_size, tag, 16);
  return S_OK;
}
HRESULT HpkeContext::Export(const BYTE* context, ULONG size, BYTE out[32]) const {
  if (!out) return E_INVALIDARG;
  SecureZeroMemory(out, 32);
  if (!ready_) return E_UNEXPECTED;
  return Label(true, false, exporter_, "sec", context, size, out, 32);
}

HRESULT HpkeSelfTest(ULONG* checks) {
  if (!checks) return E_INVALIDARG;
  *checks = 0;
  using namespace hpke_vector;
  P256Key receiver, ephemeral;
  if (FAILED(receiver.ImportTestKey(pkRm, skRm)) || FAILED(ephemeral.ImportTestKey(pkEm, skEm))) return E_FAIL;
  HpkeContext sender, recipient;
  if (FAILED(sender.Setup(ephemeral, pkRm, true, info, sizeof(info))) ||
      FAILED(recipient.SetupReceiver(receiver, pkEm, info, sizeof(info)))) return E_FAIL;
  if (!ConstantTimeEqual(sender.key_, key, sizeof(key)) ||
      !ConstantTimeEqual(sender.nonce_, base_nonce, sizeof(base_nonce)) ||
      !ConstantTimeEqual(sender.exporter_, exporter_secret, sizeof(exporter_secret))) return E_FAIL;
  *checks += 3;
  BYTE encrypted[sizeof(ct)]{}, opened[sizeof(pt)]{};
  if (FAILED(sender.Seal(aad, sizeof(aad), pt, sizeof(pt), encrypted)) ||
      !ConstantTimeEqual(encrypted, ct, sizeof(ct))) return E_FAIL;
  ++*checks;
  if (FAILED(recipient.Open(aad, sizeof(aad), ct, sizeof(ct), opened)) ||
      !ConstantTimeEqual(opened, pt, sizeof(pt))) return E_FAIL;
  ++*checks;
  if (SUCCEEDED(sender.Seal(aad, sizeof(aad), pt, sizeof(pt), encrypted)) ||
      SUCCEEDED(recipient.Open(aad, sizeof(aad), ct, sizeof(ct), opened))) return E_FAIL;
  ++*checks;
  BYTE exported[32]{};
  for (ULONG i = 0; i < 3; ++i) {
    if (FAILED(sender.Export(export_contexts[i], export_sizes[i], exported)) ||
        !ConstantTimeEqual(exported, exports[i], 32)) return E_FAIL;
    ++*checks;
  }
  SecureZeroMemory(exported, sizeof(exported));
  return S_OK;
}
}  // namespace hintless_vbs
