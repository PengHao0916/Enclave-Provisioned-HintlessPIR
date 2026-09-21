#include "installation.h"
#include "cng_primitives.h"
#include <stddef.h>

namespace hintless_vbs {
HRESULT VerifyInstallationAck(const InstallationAck& ack, const BYTE pinned_key[65]) {
  if (ack.version != 1 || ack.size != sizeof(ack) || !pinned_key || pinned_key[0] != 4) return E_INVALIDARG;
  BYTE input[sizeof(kInstallationDomain) - 1 + offsetof(InstallationAck, signature)]{};
  CopyMemory(input, kInstallationDomain, sizeof(kInstallationDomain) - 1);
  CopyMemory(input + sizeof(kInstallationDomain) - 1, &ack, offsetof(InstallationAck, signature));
  BYTE hash[32]{};
  HRESULT hr = Sha256(input, sizeof(input), hash);
  if (FAILED(hr)) return hr;
  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_KEY_HANDLE key = nullptr;
  NTSTATUS s = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0);
  BYTE blob[sizeof(BCRYPT_ECCKEY_BLOB) + 64]{};
  BCRYPT_ECCKEY_BLOB header{BCRYPT_ECDSA_PUBLIC_P256_MAGIC, 32};
  CopyMemory(blob, &header, sizeof(header)); CopyMemory(blob + sizeof(header), pinned_key + 1, 64);
  if (s >= 0) s = BCryptImportKeyPair(algorithm, nullptr, BCRYPT_ECCPUBLIC_BLOB, &key, blob, sizeof(blob), 0);
  if (s >= 0) s = BCryptVerifySignature(key, nullptr, hash, sizeof(hash),
                                        const_cast<BYTE*>(ack.signature), sizeof(ack.signature), 0);
  if (key) BCryptDestroyKey(key);
  if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
  return s < 0 ? HRESULT_FROM_NT(s) : S_OK;
}
}  // namespace hintless_vbs
