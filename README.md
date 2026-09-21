# HintlessPIR：本地一次性材料原型

当前实现分为客户端、普通 PIR 服务器、模拟 TEE 材料生成器。每个逻辑查询独立生成 LWE 秘密 s 与 RLWE 密钥 v，服务端提前保存 Enc(s) 和完整 Galois key；客户端在线上传 LWE 查询和材料编号，缓存一份静态公开响应分量。

**本项目已在本机 Windows VBS enclave 中实际执行一次性材料核心和 HPKE 通道，并完成公开固定种子的端到端查询验证；可信客户端证明验证和完整多查询安全证明仍未完成，因此尚不能作为私密生产后端。** 不需要云服务器，使用 WSL/Linux 和 Windows 原生工具运行。

Windows VBS enclave 状态见[原生代码、签名与实测状态](vbs_material/README.md)。完整材料计算核心（KDF、s/v、Enc(s)、Galois key）和 HPKE 入口已移植进非调试 enclave DLL。2026-09-21 本机已完成 `Create → Load → Initialize → Call`，隔离区内 68 项检查通过；functional/8 MiB 配置各 3 次真实 enclave 材料查询正确恢复。仍需可信客户端证明策略与正式后端集成。

2026-09-21 更新：[加密材料通道](vbs_material/CHANNEL.md)已有 HPKE、生成回执和单会话重试门控；[安装确认与客户端日志](vbs_material/LIFECYCLE.md)将服务器签名验收、发出查询前的持久化和崩溃后失效接入测试链路。Windows VBS enclave 与原 Linux PIR 的 6 次完整查询通过。测试仍使用公开固定种子和仅检查报告绑定的适配器，不能据此宣称真实远程证明或私密生产后端完成。

```bash
cd /home/ph/single-server-pir
bash local_material/run_local_validation.sh
```

- [完整接口、运行方式、参数和局限](local_material/README.md)
- [核心协议实现](local_material/protocol.cc)
- [回归测试](local_material/protocol_test.cc)
- [本地实验结果](local_material/results/)
- [旧公共掩码池说明](hintless_simplepir/SECURE_SESSION.md)
- [旧 README 归档](docs/legacy_readme.md)（其中性能和安全表述不是当前结果）

底层代码基于 [Google HintlessPIR](https://github.com/google/hintless_pir) 与 shell-encryption。
静态响应分量预计算归属于已有 HintlessPIR 构造；工程改动不构成新颖性或安全性证明。
