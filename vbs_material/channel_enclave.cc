#include <winenclave.h>
#include <new>
#include <stddef.h>
#include "material_channel.h"

namespace {
using namespace hintless_vbs;
MaterialChannelReceiver* receiver = nullptr;
volatile LONG gate = 0;
struct Lock {
  bool acquired = InterlockedCompareExchange(&gate, 1, 0) == 0;
  ~Lock() { if (acquired) InterlockedExchange(&gate, 0); }
};
void* Result(HRESULT hr) { return reinterpret_cast<void*>(static_cast<ULONG_PTR>(hr)); }
HRESULT CheckIdentity() {
  ENCLAVE_INFORMATION info{};
  HRESULT hr = EnclaveGetEnclaveInformation(sizeof(info), &info);
  if (FAILED(hr)) return hr;
  if (info.EnclaveType != ENCLAVE_TYPE_VBS ||
      (info.Identity.Flags & (ENCLAVE_FLAG_FULL_DEBUG_ENABLED |
       ENCLAVE_FLAG_DYNAMIC_DEBUG_ENABLED | ENCLAVE_FLAG_DYNAMIC_DEBUG_ACTIVE))) return E_ACCESSDENIED;
  return S_OK;
}
}  // namespace

extern "C" void* CALLBACK HintlessChannelBegin(void* untrusted) {
  using namespace hintless_vbs;
  Lock lock;
  if (!lock.acquired) return Result(HRESULT_FROM_WIN32(ERROR_BUSY));
  if (receiver) return Result(E_UNEXPECTED);
  ChannelHello hello{};
  HRESULT hr = EnclaveCopyIntoEnclave(&hello, untrusted, sizeof(hello));
  if (SUCCEEDED(hr)) hr = CheckIdentity();
  if (FAILED(hr)) return Result(hr);
  auto* offer = new (std::nothrow) ChannelOffer{};
  auto* candidate = new (std::nothrow) MaterialChannelReceiver;
  if (!offer || !candidate) { delete offer; delete candidate; return Result(E_OUTOFMEMORY); }
  hr = candidate->Begin(hello, offer);
  BYTE report_data[64]{};
  UINT32 report_size = 0;
  if (SUCCEEDED(hr)) hr = ChannelReportData(hello, *offer, report_data);
  if (SUCCEEDED(hr)) hr = EnclaveGetAttestationReport(report_data, offer->report,
                                                       kMaxReportBytes, &report_size);
  offer->report_size = report_size;
  if (SUCCEEDED(hr) && (!offer->report_size || offer->report_size > kMaxReportBytes)) hr = E_FAIL;
  if (SUCCEEDED(hr)) hr = EnclaveVerifyAttestationReport(ENCLAVE_TYPE_VBS, offer->report, offer->report_size);
  if (SUCCEEDED(hr)) hr = EnclaveCopyOutOfEnclave(
      static_cast<BYTE*>(untrusted) + offsetof(ChannelBeginExchange, reply), offer, sizeof(*offer));
  if (SUCCEEDED(hr)) receiver = candidate;
  else delete candidate;
  SecureZeroMemory(offer, sizeof(*offer)); delete offer;
  return Result(hr);
}

extern "C" void* CALLBACK HintlessChannelGenerate(void* untrusted) {
  using namespace hintless_vbs;
  Lock lock;
  if (!lock.acquired) return Result(HRESULT_FROM_WIN32(ERROR_BUSY));
  if (!receiver) return Result(E_UNEXPECTED);
  SealedPreparation request{};
  HRESULT hr = EnclaveCopyIntoEnclave(&request, untrusted, sizeof(request));
  if (FAILED(hr)) return Result(hr);
  auto* material = new (std::nothrow) RawMaterial{};
  if (!material) return Result(E_OUTOFMEMORY);
  GenerationReceipt receipt{};
  hr = receiver->Generate(request, material, &receipt);
  if (SUCCEEDED(hr)) hr = EnclaveCopyOutOfEnclave(
      static_cast<BYTE*>(untrusted) + offsetof(ChannelGenerateExchange, material), material, sizeof(*material));
  if (SUCCEEDED(hr)) hr = EnclaveCopyOutOfEnclave(
      static_cast<BYTE*>(untrusted) + offsetof(ChannelGenerateExchange, receipt), &receipt, sizeof(receipt));
  SecureZeroMemory(material, sizeof(*material)); delete material;
  SecureZeroMemory(&request, sizeof(request));
  return Result(hr);
}

extern "C" void* CALLBACK HintlessChannelClose(void* untrusted) {
  if (untrusted) return Result(E_INVALIDARG);
  Lock lock;
  if (!lock.acquired) return Result(HRESULT_FROM_WIN32(ERROR_BUSY));
  delete receiver; receiver = nullptr;
  return Result(S_OK);
}
