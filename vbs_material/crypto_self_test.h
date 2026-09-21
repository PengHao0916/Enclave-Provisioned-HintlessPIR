#ifndef HINTLESS_VBS_CRYPTO_SELF_TEST_H_
#define HINTLESS_VBS_CRYPTO_SELF_TEST_H_
#include <windows.h>
namespace hintless_vbs {
// All inputs are public fixtures, never real client material.
HRESULT CryptoSelfTest(ULONG* checks_passed);
}
#endif
