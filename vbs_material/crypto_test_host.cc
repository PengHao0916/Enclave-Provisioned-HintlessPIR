#include <stdio.h>
#include "crypto_self_test.h"
int main() {
  ULONG passed = 0;
  HRESULT hr = hintless_vbs::CryptoSelfTest(&passed);
  printf("{\"backend\":\"windows-native-compatibility-test-NOT-TEE\","
         "\"public_test_inputs_only\":true,\"checks_passed\":%lu,"
         "\"hresult\":\"0x%08lX\",\"success\":%s}\n",
         passed, static_cast<ULONG>(hr), SUCCEEDED(hr) ? "true" : "false");
  return SUCCEEDED(hr) ? 0 : 1;
}
