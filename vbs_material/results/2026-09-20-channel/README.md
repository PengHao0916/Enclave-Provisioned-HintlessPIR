# 2026-09-20 加密材料通道证据

**真实 enclave 未加载；可信客户端证明验证器未实现。** 所有成功结果均明确标为普通进程、公用测试种子。没有云服务、代码提交或推送。

| 文件 | 内容 |
| --- | --- |
| build-manifest.json | 非调试 enclave 构建、22 个编译相关文件哈希、导入白名单、工具链版本 |
| signing-manifest.json | 当前 DLL 测试页哈希签名及签名后文件哈希 |
| crypto-test-result.json | 原有 59 项原生兼容性检查 |
| channel-test-result.json | 34 项通道测试，其中 1 项汇总 9 项 RFC 9180 向量检查 |
| interop-channel-native-functional.json | 经 HPKE 种子入口和 MAC 回执后的 3 次功能配置正确查询 |
| interop-channel-native-8mb.json | 同一路径的 3 次 8 MiB 配置正确查询 |
| probe-result.json | 最新签名 DLL 实际 LoadEnclaveImageW 失败，Win32 577 |
| channel-enclave-result.json | 加密材料宿主实际加载同一 DLL 失败，HRESULT 0x80070241；未调用加密 enclave 函数 |
| environment.json | 本轮实时读取：最近开机 9 月 19 日，Secure Boot 仍开启、VBS/HVCI 运行 |
| checkpoint.json | 顶层源码哈希、工作树未提交状态和验证边界 |

两组互操作结果均包含原库对所有密文/Galois key 噪声多项式、RNS 一致性、重试与复用拒绝的检查。生成回执验证不等于安装确认。

完整协议、测试验证器边界及复现步骤见 [CHANNEL.md](../../CHANNEL.md)。9 月 18 日的日志仍保留在相邻目录，不能用旧 DLL 的结果代替本轮结果。
