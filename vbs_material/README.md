# Windows VBS enclave：一次性材料工厂接入

**2026-09-21：非调试 VBS enclave DLL 已在本机完成真实加载、初始化和调用，隔离区内 68 项检查通过；HPKE 输入、一次性材料生成、服务器安装确认和客户端日志已完成公开固定种子的端到端测试。** 可信客户端证明验证与生产传输集成尚未完成，因此没有可用于私密查询的完整生产后端。

本目录使用 Windows 原生 enclave API，无模拟器回退。`local_material/` 的三进程模拟器仍是独立的 local-simulation-NOT-TEE 后端。

## 当前证据

| 检查 | 本机结果 | 可以支持的结论 |
| --- | --- | --- |
| Windows 原生 CNG/采样兼容性 | 59 项通过 | RFC 5869 向量、原库 KDF/PRNG/采样结果兼容 |
| RFC 9180 HPKE A.3.1 | 9 项通过 | 固定套件的密钥、nonce、密文、解密、exporter 与一次性上下文检查 |
| 加密通道测试 | 34 项通过（其中 1 项汇总上述 RFC 套件） | 证明缺失、S_FALSE、替换、篡改、重放、精确重试和回执校验 |
| 完整 Windows 材料 → 原 Linux 服务器/客户端 | functional、8mb 各 3 次正确恢复 | 固定配置下完整材料的互操作性 |
| HPKE 传入种子 → 材料生成 → 原 Linux 查询 | functional、8mb 各 3 次正确恢复 | 使用公开种子和测试证明适配器的加密路径互操作性 |
| 生成回执 → 安装签名 → 持久化查询 → 解密 | functional、8mb 各 3 次正确恢复；各 4 项安装反例拒绝 | BoringSSL 签名与 Windows CNG 验签互操作、安装与查询状态门控 |
| 客户端日志故障测试 | 11 项通过 | 并发抢用、异常退出、重启失效、截断/损坏、私有权限、写盘失败等测试行为；不证明抗快照回滚 |
| 密文与 Galois key 的全部噪声多项式 | 原库核对所有 4096 个系数、各 RNS 分支，通过 | 所测样本符合预期代数关系和噪声范围 |
| 精确重试、不同请求复用、释放后使用 | 检查通过 | 测试路径的一次性状态行为 |
| DLL 编译、VEIID 绑定、测试签名 | 通过 | 原生非调试 enclave 构建产物存在 |
| VBS 支持 / CreateEnclave | true / 成功 | 平台 API 支持，真实隔离区可创建 |
| Load / Initialize / Call | 全部成功 | 实际 VBS enclave 执行，隔离区内 68 项检查通过，非 native 回退 |
| 真实 enclave 生命周期查询 | functional、8mb 各 3 次正确恢复 | 公开固定种子经过实际 enclave HPKE/材料路径，安装确认、日志、查询和恢复通过 |
| TESTSIGNING / HVCI | 生效 / 运行 | 本机开发测试条件；Secure Boot 已临时关闭，不是生产部署配置 |

原生互操作测试使用**公开固定测试种子**，不是私密客户端会话，不是 TEE 性能实验或安全证明。测试仅覆盖两个明确配置，不建立参数的安全强度或正确性失败率结论。material_payload_bytes 仅为生成的公共材料序列化大小，不是端到端通信总量。

最新真实执行证据位于 [VBS 实际执行结果](results/2026-09-21-real-vbs/)。[安装与生命周期结果](results/2026-09-21-lifecycle/)、[加密通道结果](results/2026-09-20-channel/)和[材料移植结果](results/2026-09-18-material-port/)保留较早快照，不能用旧哈希指认当前程序。协议说明见 [CHANNEL.md](CHANNEL.md) 和 [LIFECYCLE.md](LIFECYCLE.md)。

## 构造与边界

保持已确定的分工：TEE 只生成一次性材料。数据库 D、公共矩阵 A、hint H、查询位置均不进入工厂，普通服务器承担在线 PIR。

1. 客户端持有每份材料独立的 32 字节主种子和材料编号。先由可信证明验证器认证 enclave 身份、平台与通道公钥，再用 HPKE 加密种子。加密和校验门控已实现；**真实证明验证器尚未实现，默认验证器拒绝全部请求。**
2. enclave 内以配置摘要和材料编号做域分离，派生独立 LWE 秘密 s 与 RLWE 密钥 v；执行全部 CRT 分支的 Enc_v(s) 与完整 Galois key 生成。当前已完成这一计算核心的移植和编译。
3. 普通宿主得到公共材料和 HPKE exporter 派生的 MAC 生成回执。另由普通 PIR 服务器在实际安装成功后签署确认；客户端匹配两个回执的材料摘要并验签后才允许查询。已实现客户端日志的普通崩溃/重启保护；跨客户端授权、生产密钥管理和快照回滚保护仍待实现。安装签名认证服务器声明，不证明恶意服务器诚实保存。
4. 客户端之后按需选择查询位置，在线发送 LWE 查询与材料编号。普通服务器使用缓存材料计算 PIR；客户端结合静态公开响应分量恢复数据。上述 Windows 原生测试已与现有 Linux 流程互操作。

保留的 HintlessPublicMaterialTest 只接受公开测试编号。新增 HintlessChannelBegin / Generate / Close 只暴露公开参数、证明、公钥、HPKE 密文、公共材料和回执，没有明文种子入口。未接入可信证明策略的客户端不得提交私密种子。内部 GenerateMaterial 的指针参数仍仅供可信地址空间使用。

独立 s/v 阻断原稿被指出的直接掩蔽项抵消路径，不构成完整联合视图、多查询、侧信道或恶意服务端安全证明。此移植需要独立密码实现审计。缓冲区显式清理也不是编译器和平台级安全擦除证明。

## 文件职责

| 文件 | 职责 |
| --- | --- |
| cng_primitives.* | Windows CNG SHA-256、HMAC/HKDF、与原库一致的 PRNG、LWE 和 RLWE 秘密采样 |
| rlwe_material.* | 固定配置 Montgomery/NTT、BFV 编码、CRT 加密、完整 Galois key；随机噪声来自 BCrypt |
| enclave_probe.cc | 实际 enclave：受检边界拷贝、身份与非调试检查、68 项基础自检、挑战绑定报告、公开材料测试入口 |
| hpke.* / hpke_test_vector.h | RFC 9180 P-256/SHA256/AES128GCM 单报文上下文及公开标准向量 |
| material_channel.* | 证明校验门控、配置/材料/挑战/公钥绑定、HPKE 种子解密、生成回执、精确重试缓存 |
| installation* / client_journal* | 真实 PIR 安装后签名、客户端 CNG 验签与一次性门控、可信客户端文件系统上的持久化状态 |
| lifecycle_test_driver.* / validate_lifecycle.ps1 | 固定公开种子的跨平台安装、日志、查询完整验证与安装反例 |
| channel_enclave.cc | 真正的加密工厂 ABI，输入快照、非调试校验、本机报告验证、串行锁 |
| channel_test_host.cc / validate_channel.ps1 | 公开测试种子的 native/enclave 加密路径验证；测试适配器不提供真实证明认证 |
| probe_abi.h / material_test_abi.h | 有界、无嵌套指针的 ABI；材料测试入口只用公开固定种子 |
| probe_host.cc | Create → Load → Initialize → Call → Terminate/Delete；记录失败阶段，无回退 |
| material_test_host.cc | 分别调用原生核心或实际 enclave 生成公开测试材料；明确记录后端和失败阶段 |
| compatibility_oracle.cc / testdata/ | 使用原 shell-encryption 和 HintlessPIR 生成公开兼容向量 |
| crypto_self_test.* / crypto_test_host.cc | RFC 和原库向量、边界及 PRNG 状态检查 |
| material_interop_test.cc | 原库独立检查所有噪声关系，并运行原客户端/服务器的查询及重试测试 |
| build.ps1 | 严格编译、VEIID 绑定、导入白名单、非调试配置、59 项原生检查、源码与二进制哈希 |
| create_test_certificate.ps1 / sign_test.ps1 | 项目专用、不可导出的 CurrentUser/My 开发证书及页哈希签名；不加入可信根 |
| run_probe.ps1 / validate_interop.ps1 | 实际 enclave 探针及两种配置的互操作测试 |
| admin_preflight.ps1 | 管理员只读检查 Secure Boot、TPM、磁盘加密和启动项 |
| restart_to_firmware.ps1 | 手动运行后请求进入固件；不强制关闭应用，不能代操作 BIOS |
| enable_test_signing.ps1 / after_firmware.ps1 | 在用户已授权的本地开发流程中启用 TESTSIGNING，记录结果；不自行重启 |
| continue_setup.ps1 / setup_policy.ps1 | 一次性登录续跑：检查实际 TESTSIGN/HVCI、启用测试签名并在重启后验证真实 enclave；7 天过期、文件哈希检查、无自动重启或 native 回退 |
| setup_policy_test.ps1 | 设置决策的 9 项测试，不修改系统启动配置 |

DLL 的 PolicyFlags=0，宿主创建 Flags=0。平台导入限于 vertdll.dll、ucrtbase_enclave.dll、bcrypt.dll，均由 VEIID 绑定。enclave 不链接 BoringSSL、Abseil、Eigen、Protobuf；序列化和原库核对留在普通测试进程。

## 重建、签名及普通进程验证

本机实际 CPU 为 **i7-14650HX**，VBS/HVCI 正在运行，SGX/SGX2 API 支持为 false。Windows build 26200.9457；MSVC 14.44.35207；SDK 中 VEIID 版本 10.0.26100.4654。

仓库在 WSL，复制本项目源码到 Windows 本地路径构建，不修改 PowerShell 执行策略：

```powershell
$src = '\\wsl.localhost\Ubuntu\home\ph\single-server-pir\vbs_material'
$out = 'D:\04_DATA\ACM TOPS\native_tee_build'
New-Item -ItemType Directory -Path "$out\source" -Force | Out-Null
Get-ChildItem -LiteralPath $src -File | Copy-Item -Destination "$out\source" -Force
& "$out\source\build.ps1" -OutDir $out
$thumbprint = & "$out\source\create_test_certificate.ps1"
& "$out\source\sign_test.ps1" -CertificateThumbprint $thumbprint -BuildDir $out
& "$out\source\validate_interop.ps1" -Backend native
& "$out\source\validate_channel.ps1" -Backend native
& "$out\source\run_probe.ps1" -BuildDir $out
```

构建覆盖指定目录的产物，重建后必须重新签名。证书有效期 90 天，仅用于本地开发。SignTool 退出码 2 为完成但有警告，脚本同时核对嵌入证书指纹；签名不等于系统已接受它。最后一条命令当前因加载错误 577 返回非零。

原库固定版本为 shell-encryption 3b1bdfad1bf67a1414cce7bc0684a3cffd231aa3。固定参数来自 local_material::ParametersForProfile，支持 functional 和 8mb；没有宣称支持任意 HintlessPIR 参数。

## 本机固件步骤

用户已授权配置本机研究环境，9 月 18 日实际以管理员权限执行 bcdedit /set TESTSIGNING ON；Windows 因 Secure Boot 拒绝，未修改启动项。当时 TPM 正常、C/D 盘未加密（历史状态，脚本会再次核对）。9 月 20 日实查最后启动为 9 月 19 日 11:57:56，但 Secure Boot 仍为 1、VBS/HVCI 运行，最新 DLL 仍加载失败。本会话没有执行重启或关闭保护。

微软本地开发流程要求关闭 Secure Boot、开启 TESTSIGNING、重启，同时保持 Memory Integrity 开启。固件菜单无法由本会话操作，按以下顺序完成：

1. 保存工作，在 PowerShell 手动运行：

```powershell
& 'D:\04_DATA\ACM TOPS\native_tee_build\source\restart_to_firmware.ps1'
```

脚本会请求管理员权限，并使用 shutdown /r /fw /t 0，没有 /f。如应用阻止关机，先自行保存并关闭应用。若固件重启不受支持，使用 Windows 恢复设置中的高级启动。

2. 在 BIOS/UEFI 中关闭 **Secure Boot**，保留 TPM、硬件虚拟化，保存并返回 Windows。当前不猜测此型号的具体菜单名称。

3. 回到 Windows 运行：

```powershell
& 'D:\04_DATA\ACM TOPS\native_tee_build\source\after_firmware.ps1'
```

脚本确认 Secure Boot 已关闭，提权启用 TESTSIGNING，并要求本次新日志确认成功。它不会自行重启。提示成功后正常重启 Windows，保持内存完整性开启。

4. 复测：

```powershell
& 'D:\04_DATA\ACM TOPS\native_tee_build\source\run_probe.ps1' -BuildDir 'D:\04_DATA\ACM TOPS\native_tee_build'
& 'D:\04_DATA\ACM TOPS\native_tee_build\source\validate_interop.ps1' -Backend enclave
& 'D:\04_DATA\ACM TOPS\native_tee_build\source\validate_channel.ps1' -Backend enclave
```

需要实际看到 probe_validated=true、enclave 内 68 项基础检查通过，以及 enclave 模式的两组正确结果。加密 enclave 测试仍只使用公开种子，其宿主仅检查报告格式/绑定，不验证远程平台签名，不能代替真实客户端验证器。可能仍有后续平台或运行时错误，须如实处理，不以原生模式代替。

恢复环境时，管理员执行 bcdedit /set TESTSIGNING OFF，正常重启并恢复固件 Secure Boot；再核对 Memory Integrity 状态。此后测试签名 DLL 通常无法继续加载。

## 真实私密后端仍需完成

- 客户端验证 enclave 身份、版本、非调试标志和平台证明链，防止宿主伪造或替换通道公钥。
- 将已有 HPKE、生成/安装回执及日志接入真实证明策略与正式客户端传输、可信公钥分发和密钥轮换。
- 在已测单客户端并发抢用、精确重试、崩溃/重启之外，完善服务端多租户、超时、长期日志管理与快照回滚方案，移除或隔离公开测试接口。
- enclave 实际内存/时延/吞吐量、并发客户端与完整通信账本，包括证明、通道建立、回执和静态分量。
- 侧信道和实现审计、具体安全参数估计、正确性失败率推导与完整多查询安全分析。

EnclaveVerifyAttestationReport 只验证本系统的报告；其返回成功不等于远程客户端验证成功。宿主 JSON 不是安全证明。关闭 Secure Boot 的测试签名环境可用于开发执行验证，不能直接当成生产平台信任链的证据。当前 P-256 HPKE 通道提供的是经典密码学安全目标，不支持端到端后量子安全主张。

## 依据

- [VBS enclave 开发、链接和签名](https://learn.microsoft.com/en-us/windows/win32/trusted-execution/vbs-enclaves-dev-guide)
- [微软本地开发环境步骤](https://github.com/microsoft/VbsEnclaveTooling/blob/main/docs/HelloWorldWalkthrough.md)
- [TESTSIGNING 与 Secure Boot](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option)
- [VBS 中可用的 CNG API](https://learn.microsoft.com/en-us/windows/win32/trusted-execution/enclaves-available-in-bcrypt)
- [RFC 5869：HKDF](https://www.rfc-editor.org/rfc/rfc5869)
- [Windows shutdown 的固件与强制关闭选项](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/shutdown)
