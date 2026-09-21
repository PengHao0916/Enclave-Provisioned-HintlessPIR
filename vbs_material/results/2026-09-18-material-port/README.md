# 2026-09-18 材料核心移植证据

本目录保存本机这一阶段的实际结果。**真实 enclave 尚未加载成功，私密后端尚未完成。** 未提交或推送仓库。

- `build-manifest.json`：15 个编译相关源文件的哈希、工具链版本、未签名 DLL 和宿主哈希；当前仓库源码已逐项核对。
- `signing-manifest.json`：本地测试证书的页哈希签名结果；签名后 DLL 哈希应与两个 enclave 加载结果一致。
- `crypto-test-result.json`：Windows 普通进程中的 59 项兼容性检查，不是 enclave 内结果。
- `interop-native-*.json`：固定公开测试种子，functional/8mb 各 3 次正确恢复，并核对全部噪声关系、精确重试和材料复用拒绝；附测试宿主二进制哈希。
- `probe-result.json`：CreateEnclave 成功，LoadEnclaveImageW 失败 577；enclave 自检、证明生成及报告验证均未执行。
- `enclave-material-result.json`：实际材料测试入口同样在 LoadEnclaveImageW 阶段失败，HRESULT 0x80070241，没有回退到 native。
- `environment.json`：之前的本机环境检查快照，读取时间见文件；不能当作每次启动后的最新状态。
- `admin-preflight.json`：管理员只读检查结果；TPM 正常，C/D 盘当次未加密。
- `test-signing-change.json`：已获用户授权的 TESTSIGNING ON 实际尝试，被 Secure Boot 策略阻止；change_applied=false。
- `checkpoint.json`：当前顶层源码文件哈希及阶段边界；基础 Git 提交不包含这些尚未提交的更改。

测试对应 Windows 程序在本机 D:\04_DATA\ACM TOPS\native_tee_build。可执行文件和证书私钥不纳入仓库。

复现步骤和未完成项见 [上级说明](../../README.md)。公开测试材料大小不等于全生命周期通信量；兼容性检查不证明安全强度、侧信道安全或正确性失败率。
