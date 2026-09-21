#ifndef HINTLESS_VBS_MATERIAL_CHANNEL_H_
#define HINTLESS_VBS_MATERIAL_CHANNEL_H_
#include "hpke.h"
#include "rlwe_material.h"
#include "probe_abi.h"
#include "installation.h"

namespace hintless_vbs {
constexpr ULONG kChannelVersion = 1;
struct ChannelHello {
  ULONG version;
  ULONG size;
  MaterialConfig config;
  BYTE material_id[32];
  BYTE challenge[32];
};
struct ChannelOffer {
  ULONG version;
  ULONG size;
  BYTE recipient_key[65];
  BYTE reserved[3];
  BYTE transcript[32];
  ULONG report_size;
  BYTE report[kMaxReportBytes];
};
struct SealedPreparation {
  ULONG version;
  ULONG size;
  BYTE transcript[32];
  BYTE encapsulation[65];
  BYTE encrypted_seed[48];  // 32-byte seed + 16-byte GCM tag; no plaintext seed.
  BYTE reserved[3];
};
struct GenerationReceipt {
  ULONG version;
  ULONG size;
  BYTE transcript[32];
  BYTE request_digest[32];
  BYTE material_digest[32];
  BYTE mac[32];
};
static_assert(sizeof(ChannelHello) == 364, "Unexpected hello layout");
static_assert(sizeof(ChannelOffer) == 16496, "Unexpected offer layout");
static_assert(sizeof(SealedPreparation) == 156, "Unexpected sealed request layout");
static_assert(sizeof(GenerationReceipt) == 136, "Unexpected receipt layout");

HRESULT ChannelTranscript(const ChannelHello& hello, const BYTE recipient[65], BYTE digest[32]);
HRESULT ChannelReportData(const ChannelHello& hello, const ChannelOffer& offer, BYTE data[64]);

// Trusted CLIENT policy. Its implementation must validate report signatures,
// platform chain, pinned identity/version/non-debug flags and all 64 report-data
// bytes. Host-supplied booleans/JSON are never acceptable substitutes.
class AttestationVerifier {
 public:
  virtual ~AttestationVerifier() = default;
  virtual HRESULT Verify(const BYTE* report, ULONG size, const BYTE expected_data[64]) const = 0;
};
class UnavailableAttestationVerifier final : public AttestationVerifier {
 public:
  HRESULT Verify(const BYTE*, ULONG, const BYTE[64]) const override { return E_NOTIMPL; }
};

// One material per receiver instance. No persistence or snapshot-resume API.
// Only exact-byte retransmission may return the cached PUBLIC result. A new
// instance obtains a fresh key so an old sealed request cannot be replayed.
// Callers must serialize calls; the enclave ABI below supplies a nonblocking lock.
class MaterialChannelReceiver final {
 public:
  MaterialChannelReceiver() = default;
  ~MaterialChannelReceiver();
  MaterialChannelReceiver(const MaterialChannelReceiver&) = delete;
  MaterialChannelReceiver& operator=(const MaterialChannelReceiver&) = delete;
  HRESULT Begin(const ChannelHello& hello, ChannelOffer* offer);
  HRESULT Generate(const SealedPreparation& request, RawMaterial* material, GenerationReceipt* receipt);
 private:
  enum class State { kEmpty, kWaiting, kConsumed, kInvalid };
  State state_ = State::kEmpty;
  P256Key recipient_;
  ChannelHello hello_{};
  BYTE transcript_[32]{};
  RawMaterial* cached_ = nullptr;
  GenerationReceipt receipt_{};
};

class MaterialChannelClient final {
 public:
  MaterialChannelClient() = default;
  ~MaterialChannelClient();
  MaterialChannelClient(const MaterialChannelClient&) = delete;
  MaterialChannelClient& operator=(const MaterialChannelClient&) = delete;
  HRESULT Seal(const ChannelHello& expected, const ChannelOffer& offer,
               const AttestationVerifier& verifier, const BYTE master_seed[32],
               SealedPreparation* request);
  // Authenticates GENERATION, not installation on the ordinary PIR server.
  HRESULT AcceptReceipt(const GenerationReceipt& receipt);
  HRESULT BeginInstallation(const BYTE server_epoch[32], InstallationBinding* binding);
  HRESULT AcceptInstallation(const InstallationAck& ack, const BYTE pinned_server_key[65]);
  bool ReadyForQuery() const { return ready_; }
  HRESULT ConsumeForQuery();
 private:
  bool attempted_ = false;
  bool awaiting_receipt_ = false;
  BYTE transcript_[32]{};
  BYTE request_digest_[32]{};
  BYTE receipt_key_[32]{};
  BYTE configuration_id_[32]{};
  BYTE material_id_[32]{};
  bool generated_ = false;
  bool installation_attempted_ = false;
  bool awaiting_installation_ = false;
  bool ready_ = false;
  InstallationBinding installation_{};
};

// Host ABI. The wrapper snapshots request once and copies back public outputs.
struct ChannelBeginExchange { ChannelHello request; ChannelOffer reply; };
struct ChannelGenerateExchange {
  SealedPreparation request;
  RawMaterial material;
  GenerationReceipt receipt;
};
}  // namespace hintless_vbs
#endif
