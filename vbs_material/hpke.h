#ifndef HINTLESS_VBS_HPKE_H_
#define HINTLESS_VBS_HPKE_H_
#include "cng_primitives.h"

namespace hintless_vbs {
// RFC 9180 base mode: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
// This bounded implementation supports ONE message (sequence 0) per context.
// Recipient authentication is supplied by the separate attestation policy.
bool ConstantTimeEqual(const BYTE* a, const BYTE* b, ULONG size);
HRESULT HmacSha256(const BYTE key[32], const BYTE* input, ULONG size, BYTE out[32]);
class P256Key final {
 public:
  P256Key() = default;
  ~P256Key();
  P256Key(const P256Key&) = delete;
  P256Key& operator=(const P256Key&) = delete;
  HRESULT Generate(BYTE public_key[65]);
  void Reset();
 private:
  friend class HpkeContext;
  friend HRESULT HpkeSelfTest(ULONG* checks);
  HRESULT ImportTestKey(const BYTE public_key[65], const BYTE private_key[32]);
  BCRYPT_ALG_HANDLE algorithm_ = nullptr;
  BCRYPT_KEY_HANDLE key_ = nullptr;
  BYTE public_key_[65]{};
};

class HpkeContext final {
 public:
  HpkeContext() = default;
  ~HpkeContext();
  HpkeContext(const HpkeContext&) = delete;
  HpkeContext& operator=(const HpkeContext&) = delete;
  HRESULT SetupSender(const BYTE recipient[65], const BYTE* info, ULONG size,
                      BYTE encapsulation[65]);
  HRESULT SetupReceiver(const P256Key& recipient, const BYTE encapsulation[65],
                        const BYTE* info, ULONG size);
  HRESULT Seal(const BYTE* aad, ULONG aad_size, const BYTE* plaintext,
               ULONG size, BYTE* ciphertext);  // Output: size + 16 bytes.
  HRESULT Open(const BYTE* aad, ULONG aad_size, const BYTE* ciphertext,
               ULONG size, BYTE* plaintext);  // Input includes 16-byte tag.
  HRESULT Export(const BYTE* context, ULONG size, BYTE out[32]) const;
  void Reset();
 private:
  friend HRESULT HpkeSelfTest(ULONG* checks);
  HRESULT Setup(const P256Key& own, const BYTE peer[65], bool sender,
                const BYTE* info, ULONG size);
  HRESULT Aead(bool seal, const BYTE* aad, ULONG aad_size, const BYTE* input,
               ULONG size, BYTE* output);
  BYTE key_[16]{};
  BYTE nonce_[12]{};
  BYTE exporter_[32]{};
  bool ready_ = false;
  bool sender_ = false;
  bool used_ = false;
};
HRESULT HpkeSelfTest(ULONG* checks);
}  // namespace hintless_vbs
#endif
