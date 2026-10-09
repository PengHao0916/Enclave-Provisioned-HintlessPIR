# 加密材料通道：实现与证据边界

更新：2026-09-22。计算、HPKE 通道、真实 VBS 执行、安装确认和一次性查询闭环均已实现。新增研究后端使用每份材料独立生成的随机客户端种子；本机报告只验证格式、请求绑定和非调试声明，完整远程证明链尚未实现。

## 协议顺序

1. **客户端准备公开请求。** 每份材料使用独立随机主种子、材料编号和新挑战。ChannelHello 含协议版本、受支持的配置、材料编号和挑战，不含种子或查询位置。配置来自客户端确认的数据库版本与公开参数。
2. **enclave 生成临时接收密钥。** P-256 私钥在 enclave 内创建，输出公钥。它对协议套件、完整公开配置（包括所有 pad seeds）、材料编号、挑战与公钥构造规范字节串并计算 SHA-256。
3. **绑定证明。** VBS 报告的 64 字节用户数据为客户端挑战 32 字节与上述摘要 32 字节。enclave 生成报告并做本机报告检查。宿主仅转发。默认客户端验证器返回 E_NOTIMPL；必须另行实现平台签名、可信链、程序身份/版本、非调试状态与全部绑定数据的验证。
4. **客户端加密主种子。** MaterialChannelClient::Seal 只有在可信验证器返回严格的 S_OK 后才使用种子；S_FALSE 也被拒绝。采用 RFC 9180 base mode：DHKEM(P-256, HKDF-SHA256)、HKDF-SHA256、AES-128-GCM。info 和 AAD 均绑定第 2 步摘要，客户端生成一次性封装密钥。
5. **enclave 解密并生成。** 输入边界仅接收 156 字节固定结构，其中种子是 48 字节 AEAD 密文。先复制输入，校验会话和字段；仅在 AEAD 验证成功后运行原材料计算核心，产生各 CRT 分支的 Enc(s) 和完整 Galois key。解密尝试后销毁 ECDH 密钥，生成后清理主种子、派生种子和通道密钥缓冲区。
6. **输出公共材料与生成回执。** 公共材料交给普通服务器。回执包含会话摘要、完整密文请求摘要、RawMaterial 摘要，并使用 HPKE Export 的独立上下文派生 HMAC-SHA256 密钥。客户端校验 MAC 与本地请求绑定。
7. **普通服务器安装、在线 PIR。** 生成回执只确认生成。新增安装器在实际 PIR 安装成功后签署绑定材料摘要和客户端 nonce 的确认，客户端验签后才允许查询，并在发出查询前持久化状态与报文。客户端之后再选择查询位置，普通服务器执行原 PIR，客户端按原恢复流程解密。详见 [LIFECYCLE.md](LIFECYCLE.md)。

第 1—7 步的计算、报文逻辑和安装/日志链路已编码。公开回归路径使用固定种子；`enclave-private-lifecycle` 研究路径每份材料新建 32 字节随机种子，由逻辑客户端经 HPKE 封装后交给真实 VBS。完整远程证明、生产传输和操作系统级客户端/服务器隔离仍未完成。

## 实际 enclave 边界

- HintlessChannelBegin：只接收公开配置和挑战；在隔离区生成接收私钥和证明。
- HintlessChannelGenerate：只接收加密种子请求；返回公共材料和 MAC 生成回执。
- HintlessChannelClose：销毁当前会话及公共重试缓存，允许下一会话使用新密钥。

每个 enclave 实例同时只支持一个会话。三种入口通过非阻塞锁串行化，繁忙时返回 ERROR_BUSY；这是功能实现，不是并发吞吐优化。TEE 不接收 D、A、H 或查询索引；协议中的公开配置仅包含配置 ID、固定 profile 和 pad seeds。

HPKEContext 被限制为一条消息（序号 0），同一上下文不能再次 Seal/Open，包括认证失败后的 Open。应用层重试返回已缓存的公共结果，不重新使用 nonce 加密。当前实现没有通用流式 HPKE 接口。

## 状态与重放

- 工厂状态：EMPTY → WAITING → CONSUMED，失败进入 INVALID。
- WAITING 接收异常版本、保留位、会话、曲线点、密文或标签时，当前接收密钥失效。
- CONSUMED 仅接受请求摘要完全相同的重传，返回完全相同的公共材料和回执；其他请求拒绝。
- 客户端只尝试一次 Seal；回执成功或失败都会消费回执等待状态，不能二次转移。
- 新实例/Close 后的新会话生成新的接收密钥，所以原密文报文不能直接在新会话解密。

这些是**活跃进程内状态与普通重启测试**。没有可信单调计数器、持久化防重放数据库或快照回滚防护，不能将其描述成抵御虚拟机快照、平台回滚或客户端状态回滚。调用者仍须为每个新逻辑查询使用独立主种子与编号；重新加密同一主种子/编号不会自动得到独立 s/v。攻击者可通过关闭会话或占用槽位造成拒绝服务；当前协议不保证可用性，也未实现客户端身份授权。

## 证据与测试适配器

运行 build.ps1 会执行：

- 原有 59 项 HKDF/PRNG/采样兼容性检查。
- RFC 9180 A.3.1 的 9 项检查：密钥、nonce、exporter secret、确定性密文、解密、单次使用、3 个导出向量。
- 通道测试共 34 项，其中 1 项是上述 RFC 套件汇总，其余 33 项检查证明缺失、S_FALSE、绑定替换、非法曲线点、密文/标签/回执篡改、状态与重试行为。

validate_channel.ps1 -Backend native 进一步完成 functional、8mb 各 3 次原 Linux 客户端/服务器查询，检查全部密文/Galois key 的噪声关系、RNS 一致性、精确重试和释放/复用拒绝。

**测试适配器绝非可信证明服务：**

- native 路径使用 PublicFixtureVerifier，仅核对公开测试报文。
- enclave 公开诊断路径使用 PublicReportBindingOnlyVerifier，只核对报告格式、绑定和声明的非调试字段，不认证平台签名。它只能搭配代码内预定的公开种子。
- 私密研究路径也使用 PublicReportBindingOnlyVerifier，因此只适合论文级本机实验。随机种子通过继承管道进入逻辑客户端进程；普通 PIR 服务器接收的只有公共材料。结果文件明确记录 `real_attestation_verified=false` 和 `client_server_process_isolation=false`。
- 这些适配器仅编译进 channel_test_host.exe，不链接到 enclave DLL，也不作为默认客户端验证器。私密入口不是可部署的网络 API。
- UnavailableAttestationVerifier 是未配置真实验证策略时的默认实现，拒绝请求。宿主给出的布尔值、JSON 或“本机验证成功”不能替代可信客户端验证。

测试向量来自 RFC 9180 对应 CFRG JSON；选择的数据和下载文件摘要保存在 testdata/hpke-p256-base.json，固定头文件 hpke_test_vector.h 纳入构建哈希。

## 本地复现

```powershell
$out = 'D:\04_DATA\ACM TOPS\native_tee_build'
& "$out\source\build.ps1" -OutDir $out
& "$out\source\validate_channel.ps1" -Backend native
```

重建后需重新签名；配置好固件/测试签名后再运行：

```powershell
& "$out\source\run_probe.ps1" -BuildDir $out
& "$out\source\validate_channel.ps1" -Backend enclave
& "$out\source\validate_private_backend.ps1" -Runs 10
```

9 月 22 日的私密研究后端在同一签名 DLL 上完成 functional、8mb 各 10 轮、30 次正确查询；全部噪声/RNS 关系、精确重试和复用拒绝检查通过。8mb 的 VBS 材料生命周期均值为 67.77 ms，服务器处理均值为 281.00 ms，在线总时延均值为 324.91 ms。完整统计位于 `private-vbs-research-results.json`。

## 通信与安全范围

本地 ABI 的 ChannelHello 为 364 字节，密文请求为 156 字节，生成回执为 136 字节；ChannelOffer 预留 16 KiB 报告容量。完整 RawMaterial 为 589,896 字节，并交给原服务器序列化。以上只是结构大小，不是网络实测，不包括完整证明链、传输封装、安装确认、错误重试、静态下载分量等成本。不能据此宣称端到端节省比例。

当前套件是经典 P-256 通道，不能据 RLWE/LWE 层就宣称整体具有后量子安全。HPKE base mode 本身不认证接收公钥，认证必须来自可信证明验证；它也不提供客户端身份授权。代码的功能测试不构成完整安全证明、恒定时间证明或平台级安全擦除证明。

## 官方依据

- [RFC 9180：HPKE、套件和 A.3.1 测试向量](https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.3.1)
- [CNG 原始 ECDH 结果的字节序](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptderivekey)：返回小端，实现转换为 P-256 HPKE 所需大端表示，并由标准向量核验。
- [VBS 可用的 BCrypt API](https://learn.microsoft.com/en-us/windows/win32/trusted-execution/enclaves-available-in-bcrypt)
- [EnclaveVerifyAttestationReport](https://learn.microsoft.com/en-us/windows/win32/api/winenclaveapi/nf-winenclaveapi-enclaveverifyattestationreport)：本系统 enclave 间的验证接口，不能直接用作远程客户端验证器。
