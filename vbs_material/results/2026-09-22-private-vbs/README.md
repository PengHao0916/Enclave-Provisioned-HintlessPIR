# 私密种子真实 VBS 闭环与论文级验证

日期：2026-09-22

## 结论

代码层面的论文级可行性验证已经闭合。当前实现不再只用公开固定种子：每份材料由逻辑客户端生成新的 32 字节随机主种子，经 HPKE 加密后送入真实 Windows VBS enclave；enclave 派生独立的 `s_t` 与 `v_t`，生成 `Enc(v_t, s_t)` 和完整 Galois key。普通 PIR 服务器只接收公共材料，查询位置在材料安装完成后才选择。

functional 与 8mb 两个配置各运行 10 轮，每轮查询首、尾、中间三个位置，共 30 次；60 次查询全部恢复正确。全部样本同时通过 RLWE/Galois key 噪声关系、RNS 一致性、精确重试和材料复用拒绝检查。Linux 客户端日志的 11 项故障测试也通过。

这足以支持“私密随机种子经过真实 VBS 的 HintlessPIR 一次性材料后端在本机可执行、功能正确，并有重复性能统计”的论文实验结论。它不能支持生产级远程证明、操作系统级客户端/服务器隔离、抗侧信道或快照回滚结论。

## 完整执行链

1. 研究驱动程序为每份材料生成独立的 32 字节主种子、材料编号和挑战。没有把种子写入请求文件。
2. 种子通过继承的二进制管道进入 Windows 逻辑客户端帮助进程。输入结构中的明文种子在复制后立即清理。
3. Windows 宿主创建并加载非调试 VBS enclave，调用 `HintlessChannelBegin`。enclave 在隔离区生成临时 P-256 接收密钥与绑定报告。
4. 逻辑客户端核对本机报告格式、请求绑定和非调试声明，再使用 RFC 9180 P-256/SHA-256/AES-128-GCM HPKE 封装主种子。这里是本机报告绑定验证，不是完整远程证明。
5. `HintlessChannelGenerate` 在 enclave 内解密种子、域分离派生 `s_t` 和 `v_t`，生成全部 CRT 分支的 `Enc(v_t,s_t)` 与 Galois key，并返回公共材料和带 MAC 的生成回执。
6. 普通服务器安装公共材料，检查错误 epoch 和错误材料摘要均被拒绝，随后签署安装确认。精确安装重试返回字节完全相同的确认。
7. 客户端验证生成回执和安装确认后，把该材料状态转为可查询。查询索引此时才选定，因此不是预先固定索引的批查询。
8. 原 HintlessPIR 客户端生成 LWE 查询，普通服务器执行 `Handle(query)`，客户端走原恢复关系解密记录。
9. 材料在发出一次新逻辑查询后被消费；第二次消费、改变请求、释放后复用和日志重开后的复用均被拒绝。

## 重复实验结果

全部时间均为本机应用层实测。每个配置有 30 个样本；标准差为样本标准差。材料生命周期采用冷路径，每份材料新建帮助进程并重新加载 enclave。

| 配置与阶段 | 均值 | 中位数 | 标准差 | P95 |
| --- | ---: | ---: | ---: | ---: |
| functional：enclave 加载 | 30.97 ms | 30.02 ms | 3.23 ms | 36.29 ms |
| functional：enclave 材料生成 | 25.53 ms | 24.71 ms | 2.22 ms | 29.43 ms |
| functional：材料完整生命周期 | 70.12 ms | 68.53 ms | 5.40 ms | 78.74 ms |
| functional：服务器处理 | 5.07 ms | 5.06 ms | 0.20 ms | 5.48 ms |
| functional：在线总时延 | 16.25 ms | 15.97 ms | 0.66 ms | 17.94 ms |
| 8mb：enclave 加载 | 29.07 ms | 28.01 ms | 2.48 ms | 34.59 ms |
| 8mb：enclave 材料生成 | 24.84 ms | 24.34 ms | 1.37 ms | 27.47 ms |
| 8mb：材料完整生命周期 | 67.77 ms | 66.84 ms | 3.72 ms | 74.32 ms |
| 8mb：服务器处理 | 281.00 ms | 276.66 ms | 12.24 ms | 301.64 ms |
| 8mb：在线总时延 | 324.91 ms | 320.22 ms | 13.41 ms | 346.56 ms |

8 MiB 数据库除以服务器 `Handle(query)` 均值，服务器吞吐率为 **28.47 MiB/s**，查询率为 **3.56 query/s**。在线总查询率为 **3.08 query/s**。如果把冷材料生命周期与在线阶段完全串行相加，总时间为 392.69 ms，对应 2.55 query/s；材料可在索引确定前离线准备，因此论文中应把这一口径单列，不能冒充在线服务器吞吐。

相同硬件上，旧的 10 次本地路径结果为 270.23 ms、29.60 MiB/s；新的真实私密 VBS 路径为 281.00 ms、28.47 MiB/s，服务器阶段慢约 4.0%。两次实验样本数和执行链不同，只能作为工程对照。原稿 8 MiB 表格的优化方案为 248 ms、32 MB/s；当前结果比该数慢，但已包含新构造下逐查询独立材料、真实 VBS 通道和 30 个重复样本的验证。

## 产物与可复现命令

- 汇总结果：`D:\04_DATA\ACM TOPS\native_tee_build\private-vbs-research-results.json`
- 验证清单：`D:\04_DATA\ACM TOPS\native_tee_build\verification-manifest.json`
- 复现脚本：`D:\04_DATA\ACM TOPS\native_tee_build\source\validate_private_backend.ps1`
- 已签名 enclave SHA-256：`D04404EDEF101F064DD591B3B6460E515D6CDAE7BBC23C4E5C14542BF901B81B`
- 客户端帮助程序 SHA-256：`BFD4D483F9373EA6766234715E8AB5A2C1A04F7FBF01F4A341A37927535DB6D7`

```powershell
$out = 'D:\04_DATA\ACM TOPS\native_tee_build'
& "$out\source\run_probe.ps1" -BuildDir $out
& "$out\source\validate_channel.ps1" -Backend enclave
& "$out\source\validate_lifecycle.ps1" -Backend enclave
& "$out\source\validate_private_backend.ps1" -Runs 10
```

私密实验目录只保留公共 `.material.bin` 与空的后端日志，没有 seed 或 request 文件。结果 JSON 记录 `public_test_secrets_only=false`、`private_seed_channel_executed=true` 和 `private_material_backend_implemented=true`，同时保留 `real_attestation_verified=false` 与 `client_server_process_isolation=false`，防止把研究原型误写成生产后端。

`probe-result.json` 是通用 VBS ABI/自检探针，其旧字段 `private_material_backend_implemented=false` 表示该探针本身没有执行私密材料协议，不能用来覆盖专用验证脚本的结果。私密后端状态应以 `private-vbs-research-results.json` 为准。

## 论文中可写与不可写的边界

可以写：真实非调试 VBS 执行、随机私密客户端种子的 HPKE 通道、逐查询独立 `s_t/v_t`、一次性材料状态、原 PIR 恢复正确性、30 样本分阶段性能、错误安装与复用拒绝。

不能写：远程证明链已验证、服务器宿主无法观察逻辑客户端进程、抗 VM 快照回滚、生产级安全擦除、侧信道安全、完整恶意服务器安全，以及仅凭测试就已证明多查询安全。`real_attestation_verified=false` 的含义是完整远程信任链仍未实现；它不否定本机真实 VBS 路径已经执行。
