#include "material_channel.h"
#include <stddef.h>

namespace hintless_vbs {
namespace {
constexpr BYTE kReceiptContext[] = "HintlessPIR/VBS/material-generation-receipt/v1";
template <ULONG N> struct Secret {
  BYTE data[N]{};
  ~Secret() { SecureZeroMemory(data, N); }
};
bool ValidHello(const ChannelHello& h) {
  return h.version == kChannelVersion && h.size == sizeof(h) &&
      (h.config.profile == MaterialProfile::kFunctional || h.config.profile == MaterialProfile::kEightMiB);
}
bool ZeroReserved(const BYTE bytes[3]) { return (bytes[0] | bytes[1] | bytes[2]) == 0; }
HRESULT ReceiptMac(const BYTE key[32], const GenerationReceipt& receipt, BYTE out[32]) {
  return HmacSha256(key, reinterpret_cast<const BYTE*>(&receipt),
                    static_cast<ULONG>(offsetof(GenerationReceipt, mac)), out);
}
}  // namespace

HRESULT ChannelTranscript(const ChannelHello& hello, const BYTE recipient[65], BYTE digest[32]) {
  if (!ValidHello(hello) || !recipient || !digest) return E_INVALIDARG;
  // Explicit serialization: domain || BE32(version) || BE32(profile) || public
  // configuration || material ID || challenge || SEC1 recipient key. No padding.
  constexpr BYTE domain[] = "HintlessPIR/VBS/HPKE-P256-SHA256-AES128GCM/v1";
  BYTE bytes[sizeof(domain) - 1 + 8 + 288 + 64 + 65]{};
  ULONG n = sizeof(domain) - 1;
  CopyMemory(bytes, domain, n);
  const ULONG values[] = {hello.version, static_cast<ULONG>(hello.config.profile)};
  for (ULONG value : values) for (int shift = 24; shift >= 0; shift -= 8) bytes[n++] = static_cast<BYTE>(value >> shift);
  CopyMemory(bytes + n, hello.config.configuration_id, 32); n += 32;
  CopyMemory(bytes + n, hello.config.ciphertext_pad_seeds, 192); n += 192;
  CopyMemory(bytes + n, hello.config.galois_pad_seed, 64); n += 64;
  CopyMemory(bytes + n, hello.material_id, 32); n += 32;
  CopyMemory(bytes + n, hello.challenge, 32); n += 32;
  CopyMemory(bytes + n, recipient, 65); n += 65;
  return Sha256(bytes, n, digest);
}
HRESULT ChannelReportData(const ChannelHello& hello, const ChannelOffer& offer, BYTE data[64]) {
  if (!data) return E_INVALIDARG;
  SecureZeroMemory(data, 64);
  HRESULT hr = ChannelTranscript(hello, offer.recipient_key, data + 32);
  if (SUCCEEDED(hr)) CopyMemory(data, hello.challenge, 32);
  return hr;
}

MaterialChannelReceiver::~MaterialChannelReceiver() {
  recipient_.Reset();
  if (cached_) { SecureZeroMemory(cached_, sizeof(*cached_)); HeapFree(GetProcessHeap(), 0, cached_); }
  SecureZeroMemory(&hello_, sizeof(hello_));
  SecureZeroMemory(&receipt_, sizeof(receipt_));
}
HRESULT MaterialChannelReceiver::Begin(const ChannelHello& hello, ChannelOffer* offer) {
  if (!offer) return E_INVALIDARG;
  SecureZeroMemory(offer, sizeof(*offer));
  if (state_ != State::kEmpty) return E_UNEXPECTED;
  state_ = State::kInvalid;
  if (!ValidHello(hello)) return E_INVALIDARG;
  HRESULT hr = recipient_.Generate(offer->recipient_key);
  if (SUCCEEDED(hr)) hr = ChannelTranscript(hello, offer->recipient_key, transcript_);
  if (FAILED(hr)) { recipient_.Reset(); SecureZeroMemory(offer, sizeof(*offer)); return hr; }
  hello_ = hello;
  offer->version = kChannelVersion; offer->size = sizeof(*offer);
  CopyMemory(offer->transcript, transcript_, 32);
  state_ = State::kWaiting;
  return S_OK;  // Report must be supplied by the real enclave wrapper.
}
HRESULT MaterialChannelReceiver::Generate(const SealedPreparation& request,
                                           RawMaterial* material, GenerationReceipt* receipt) {
  if (!material || !receipt) return E_INVALIDARG;
  SecureZeroMemory(material, sizeof(*material)); SecureZeroMemory(receipt, sizeof(*receipt));
  if (state_ != State::kWaiting && state_ != State::kConsumed) return E_UNEXPECTED;
  BYTE digest[32]{};
  HRESULT hr = Sha256(reinterpret_cast<const BYTE*>(&request), sizeof(request), digest);
  if (state_ == State::kConsumed) {
    if (FAILED(hr) || !ConstantTimeEqual(digest, receipt_.request_digest, 32)) return E_ACCESSDENIED;
    CopyMemory(material, cached_, sizeof(*material)); *receipt = receipt_;
    return S_OK;
  }
  state_ = State::kInvalid;  // Any uncertain failure burns this receiver key.
  if (request.version != kChannelVersion || request.size != sizeof(request) ||
      !ZeroReserved(request.reserved) || !ConstantTimeEqual(request.transcript, transcript_, 32)) {
    recipient_.Reset(); return E_INVALIDARG;
  }
  HpkeContext hpke;
  if (SUCCEEDED(hr)) hr = hpke.SetupReceiver(recipient_, request.encapsulation, transcript_, 32);
  recipient_.Reset();  // No reason to retain the ECDH private key after setup.
  Secret<32> master, receipt_key;
  if (SUCCEEDED(hr)) hr = hpke.Open(transcript_, 32, request.encrypted_seed, 48, master.data);
  if (SUCCEEDED(hr)) hr = hpke.Export(kReceiptContext, sizeof(kReceiptContext) - 1, receipt_key.data);
  hpke.Reset();
  if (SUCCEEDED(hr)) hr = GenerateMaterial(hello_.config, hello_.material_id, master.data, material);
  SecureZeroMemory(master.data, 32);
  if (FAILED(hr)) { SecureZeroMemory(material, sizeof(*material)); return hr; }
  receipt->version = kChannelVersion; receipt->size = sizeof(*receipt);
  CopyMemory(receipt->transcript, transcript_, 32); CopyMemory(receipt->request_digest, digest, 32);
  hr = Sha256(reinterpret_cast<const BYTE*>(material), sizeof(*material), receipt->material_digest);
  if (SUCCEEDED(hr)) hr = ReceiptMac(receipt_key.data, *receipt, receipt->mac);
  if (SUCCEEDED(hr)) {
    cached_ = static_cast<RawMaterial*>(HeapAlloc(GetProcessHeap(), 0, sizeof(*cached_)));
    if (!cached_) hr = E_OUTOFMEMORY;
  }
  if (FAILED(hr)) { SecureZeroMemory(material, sizeof(*material)); SecureZeroMemory(receipt, sizeof(*receipt)); return hr; }
  CopyMemory(cached_, material, sizeof(*material)); receipt_ = *receipt;
  state_ = State::kConsumed;
  return S_OK;
}

MaterialChannelClient::~MaterialChannelClient() { SecureZeroMemory(receipt_key_, 32); }
HRESULT MaterialChannelClient::Seal(const ChannelHello& expected, const ChannelOffer& offer,
                                    const AttestationVerifier& verifier, const BYTE master_seed[32],
                                    SealedPreparation* request) {
  if (!request) return E_INVALIDARG;
  SecureZeroMemory(request, sizeof(*request));
  if (attempted_) return E_UNEXPECTED;
  attempted_ = true;
  if (!master_seed || offer.version != kChannelVersion || offer.size != sizeof(offer) ||
      !ZeroReserved(offer.reserved) || !offer.report_size || offer.report_size > kMaxReportBytes) return E_INVALIDARG;
  BYTE report_data[64]{};
  HRESULT hr = ChannelReportData(expected, offer, report_data);
  if (FAILED(hr)) return hr;
  if (!ConstantTimeEqual(report_data + 32, offer.transcript, 32)) return E_ACCESSDENIED;
  // EXACT S_OK is required: S_FALSE/unsupported/host claims are not approval.
  hr = verifier.Verify(offer.report, offer.report_size, report_data);
  if (hr != S_OK) return FAILED(hr) ? hr : E_ACCESSDENIED;
  CopyMemory(transcript_, offer.transcript, 32);
  CopyMemory(configuration_id_, expected.config.configuration_id, 32);
  CopyMemory(material_id_, expected.material_id, 32);
  HpkeContext hpke;
  hr = hpke.SetupSender(offer.recipient_key, transcript_, 32, request->encapsulation);
  if (SUCCEEDED(hr)) hr = hpke.Seal(transcript_, 32, master_seed, 32, request->encrypted_seed);
  if (SUCCEEDED(hr)) hr = hpke.Export(kReceiptContext, sizeof(kReceiptContext) - 1, receipt_key_);
  if (SUCCEEDED(hr)) {
    request->version = kChannelVersion; request->size = sizeof(*request);
    CopyMemory(request->transcript, transcript_, 32);
    hr = Sha256(reinterpret_cast<const BYTE*>(request), sizeof(*request), request_digest_);
  }
  if (FAILED(hr)) { SecureZeroMemory(request, sizeof(*request)); SecureZeroMemory(receipt_key_, 32); return hr; }
  awaiting_receipt_ = true;
  return S_OK;
}
HRESULT MaterialChannelClient::AcceptReceipt(const GenerationReceipt& receipt) {
  if (!awaiting_receipt_) return E_UNEXPECTED;
  awaiting_receipt_ = false;
  BYTE mac[32]{};
  HRESULT hr = ReceiptMac(receipt_key_, receipt, mac);
  SecureZeroMemory(receipt_key_, 32);
  const bool match = receipt.version == kChannelVersion && receipt.size == sizeof(receipt) &&
      ConstantTimeEqual(receipt.transcript, transcript_, 32) &&
      ConstantTimeEqual(receipt.request_digest, request_digest_, 32) &&
      ConstantTimeEqual(receipt.mac, mac, 32);
  SecureZeroMemory(mac, sizeof(mac));
  if (FAILED(hr) || !match) return E_ACCESSDENIED;
  CopyMemory(installation_.configuration_id, configuration_id_, 32);
  CopyMemory(installation_.material_id, material_id_, 32);
  CopyMemory(installation_.material_digest, receipt.material_digest, 32);
  hr = Sha256(reinterpret_cast<const BYTE*>(&receipt), sizeof(receipt), installation_.generation_receipt_digest);
  generated_ = SUCCEEDED(hr);
  return hr;
}
HRESULT MaterialChannelClient::BeginInstallation(const BYTE server_epoch[32], InstallationBinding* binding) {
  if (!binding) return E_INVALIDARG;
  SecureZeroMemory(binding, sizeof(*binding));
  if (!generated_ || installation_attempted_ || !server_epoch) return E_UNEXPECTED;
  installation_attempted_ = true;
  CopyMemory(installation_.server_epoch, server_epoch, 32);
  NTSTATUS s = BCryptGenRandom(nullptr, installation_.client_nonce, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if (s < 0) return HRESULT_FROM_NT(s);
  *binding = installation_;
  awaiting_installation_ = true;
  return S_OK;
}
HRESULT MaterialChannelClient::AcceptInstallation(const InstallationAck& ack, const BYTE pinned_server_key[65]) {
  if (!awaiting_installation_) return E_UNEXPECTED;
  awaiting_installation_ = false;
  if (!ConstantTimeEqual(reinterpret_cast<const BYTE*>(&ack.binding),
                         reinterpret_cast<const BYTE*>(&installation_), sizeof(installation_))) return E_ACCESSDENIED;
  HRESULT hr = VerifyInstallationAck(ack, pinned_server_key);
  ready_ = hr == S_OK;
  return hr;
}
HRESULT MaterialChannelClient::ConsumeForQuery() {
  if (!ready_) return E_UNEXPECTED;
  ready_ = false;
  return S_OK;
}
}  // namespace hintless_vbs
