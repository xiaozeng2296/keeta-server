# 首阶段本地 a7 / a8 复现

> 历史研究资料，来源 `codex/keeta-project@6197c528`；保留当时的观测与未完成项，不代表新项目当前状态。当前规则见 [字段状态](../MTGSIG_FIELDS_STATUS.md)，复跑入口及已修正结论见 [离线研究指南](../research/OFFLINE_RESEARCH.md)。文中的旧 `dump/`、抓包及设备路径仅作证据索引，原材料未随仓库发布。

`mtgsig/local_identity.py` 已实现本地 a8 生成/解析、本地 a7 加密/解密和加密前文本构造。
两份真实抓包中的首阶段 a7 均可解密、解析并重新加密成原值；其中包含的本地 a8
均通过 CRC 校验并可从 UUID、毫秒时间重建。服务端下发值仍需按响应更新，不能由本地候选推断。

## 代码接口

- `generate_local_dfp(uuid_value, timestamp_ms, *, profile=...) -> str`
- `decode_local_dfp(value, *, profile=...) -> DecodedLocalIdentity`
- `build_local_xid_plaintext(dfp_id, timestamp_seconds) -> bytes`
- `encode_local_xid(dfp_id, timestamp_seconds, *, profile=...) -> str`
- `decode_local_xid(value, *, profile=...) -> DecodedLocalXid`

时间和 UUID 均由调用方明确传入，不隐式读取时钟。解析结果保留 profile 版本和来源。
`LocalIdentityProfile` 可覆盖 mask、布局标记、版本和来源；`LocalXidProfile` 可覆盖 AES key、
IV、版本和来源。默认值对应当前 Keeta iOS 3.12.401 / SAKGuard 5.21.10 证据。

## 新设备 bootstrap

`mtgsig/bootstrap_identity.py` 提供 `bootstrap_identity(uuid_value, timestamp_ms, *, base=None)`，
按显式 UUID 和毫秒时间生成首阶段本地 a8，以及包含该 a8 的本地 a7。这里的 UUID 是本地
ID 的随机材料，不是 `mtgsig.a1`；`a1` 属于 SDK 参数，不能用此 UUID 替代。

```bash
python3 -m mtgsig.bootstrap_identity \
  --uuid 00112233-4455-4677-8899-aabbccddeeff \
  --timestamp-ms 1700000000123 \
  --output new-local-identity.json
```

示例时间和 UUID 都是合成输入。输出文件权限为 `0600`，已存在时拒绝覆盖。
不传 `--output` 时只向标准输出写 JSON；`--base sdk-device-profile.json` 可合并已知字段。
函数深复制 base，不修改调用方对象；已有本地身份与输入不符、或 a7/a8 不能明确归类时拒绝合并。
显式 `a7_server_xid`/`xid`、`a8_server_dfp`/`dfp` 优先成为当前 a7/a8，本地候选保留在独立字段。

单独生成的文件只是身份补丁，不是完整可用设备档：不会编造 `a1`、a5 的 `base_collect`
或 a9 的 `base_siua`，缺少的签名字段列在 `local_identity_bootstrap.missing_signer_fields`。
该列表为空也仅表示必要字段已提供，不代表画像真实性、注册成功或登录可用。
服务端响应仍由 `mtgsig.registration_state` 更新；此工具不发送请求、不触发手机新机操作。

```bash
python3 -m unittest discover -s tests -p test_bootstrap_identity.py -v
```

## a8：28 字节结构加固定 XOR

首阶段 `getFingerprintID` 在缓存不可用时回退到 `SAKGuardLocalIDKeychainStorage.localID`。
其生成过程为：

```text
u = NSUUID.UUID.UUIDString 删除 '-' 并转小写              32 hex
t = floor(NSDate.timeIntervalSince1970 * 1000) 的小写hex   当前为11 hex
material = '0000' + u + t + '1'                          48 ASCII字符
crc = CRC32(material的ASCII字节)                         8小写hex
raw = hex_decode(material + crc)                        28字节
a8_local = hex_lower(raw XOR 固定28字节mask)              56字符
```

原生 CRC 包装的中间步骤是 `%016u` 输出十进制、`longLongValue` 读回整数、`%08llx`
写成十六进制。因此最终等价于常规 CRC32 的八字符十六进制。CRC 输入是 48 个 ASCII
十六进制字符，不是把它们先解码成 24 字节。

此前仅根据 56 字符长度推断 SHA224 不成立；这里能恢复 UUID、时间和 CRC，且重建匹配实包。
服务端 DFP 也可能是 56 hex，解析时必须同时通过布局和 CRC。模块不会只按长度把它当成本地 ID。

本地值由 `com.sakguard.localid` 持久缓存，并通过 `dispatch_once` 缓存在进程中。
已有效的 `static_dfpID` / 指纹存储结果优先于本地回退值。

## a7：66 字节文本的 AES-CBC

Keeta 自身的 `generateLocalXID` 选择 56 字符的 `static_dfpID`；若没有合格值，
读取缓存 localID。它构造：

```text
plaintext = ASCII('1' + selected_dfp_id + '1' + format(epoch_seconds, '%2X'))
local_a7  = Base64(AES-128-CBC(PKCS7(plaintext), fixed_key, IV))
IV        = ASCII('0102030405060708')
```

`%2X` 是最少两列的大写十六进制，当前秒时间占八列，所以文本共 `1 + 56 + 1 + 8 = 66` 字节。
填充后 80 字节，Base64 后 108 字符。不能以此长度单独判断某个服务端 XID 可解。

`+[SAKGuardCommon encrypt:]` 的入参是 NSData。它把 `[data, "aesKey"]` 传给
`NativeBridge call:withParam:` 的操作码 2。Keeta 的直接证据如此，不能仅借国内参考的
`main(1/2)` 注释断言所有阶段均相同。

受控 native 实验 `dump/envelope_recovery/local_xid_crypto_01.json` 使用三组纯合成文本：
1、16、66 字节；返回密文长度分别 16、32、80 字节。捕获 AES 核每块输入、输出、轮密钥后，
按轮密钥首 16 字节每四字节反序恢复主密钥。Python AES-CBC 的全部密文逐字匹配 native 返回值；
严格 PKCS7 解密也还原三组文本。主密钥只在实现和本地原始证据中保留，不在本文展示。

`generateLocalXID` 会写 `currLocalXid`；上面的合成实验直接调用 NSData 的 `encrypt:` wrapper，
没有调用生成器或清空缓存。NativeBridge 更深层的所有副作用未做通用保证。

## 真实抓包核验

| 抓包 | fingerprint info 索引 | a7解密长度 | 内嵌localID的CRC/重建 | 内嵌localID生成毫秒 | a7生成秒 |
|---|---:|---:|---|---:|---:|
| `从app初次打开到登录被拦截.chlsj` | 96 | 66 | 两项通过 | 1790130749677 | 1790130749 |
| `新机之后尝试登录.chlsj` | 65 | 66 | 两项通过 | 1790496483002 | 1790496483 |

新机抓包首个 `mtgsig.a8`（索引 13）就是 a7 内嵌的 localID。到 fingerprint info 时，
`/v5/sign` 已返回服务端 DFP，因此那条请求的当前 a8 已经不同。这是时间顺序的真实状态转换，
不能强制要求 a7 内嵌 ID 等于任何时刻的当前 a8。

旧包可见的首个 a8 已非该内嵌 localID，仍能独立用内嵌结构和 CRC 验证。
两包 info 响应 `data.result` 用本地 a7 解码器均未通过严格解密校验；继续将它们作为服务端 XID
原样保存，再供后续签名使用。

## 证据位置与复跑

| 证据 | 位置 |
|---|---|
| a8读取优先级与localID回退 | `dump/Keeta.dec.asm:1233555`，`getFingerprintID` |
| 持久缓存及缺失时生成 | `dump/Keeta.dec.asm:1271882`，`localID` / `sub_100363088` |
| localID布局、UUID、时间和CRC调用 | `dump/Keeta.dec.asm:1272012`，K+0x36316c |
| 固定XOR循环与28字节限制 | `dump/Keeta.dec.asm:1272684`，K+0x363ab0 |
| CRC32 wrapper | `dump/Keeta.dec.asm:1119812`，K+0x2efef8 |
| 标准反射CRC32表和运算 | `dump/Keeta.dec.asm:1110310`，K+0x2e83d4 / 表K+0x3308b64 |
| a7文本选择和构造 | `dump/Keeta.dec.asm:1236691`，`generateLocalXID` |
| NSData加密包装与op 2 | `dump/Keeta.dec.asm:1230426`，`+[SAKGuardCommon encrypt:]` |
| native合成输入、块输出 | `dump/envelope_recovery/local_xid_crypto_01.json` |

固定 mask 来自 K+0x3322c80 的 28 字节，使用已确认的字符串解混淆规则
`dst[i] = src[i] XOR ((0xeb + 3*i) & 255)`。已用 Mach-O segment 映射确认本段 RVA 与文件偏移一致。
两类固定值的来源、测试数量和样本摘要另外保存在 `dump/local_identity_recovery/verification.json`。

```bash
python3 -m unittest discover -s tests -p test_local_identity.py -v
```

测试覆盖 native 三组向量、两份真实 a7 的严格解密与逐字重加密、内嵌 localID 的 CRC/重建、
首个新机 a8 的重建、profile 覆盖、错误输入、有效padding但格式错误的密文。
真实身份内容只读取现有本地抓包，不复制到测试源码或控制台；抓包未分发时对应测试明确 skip。

`dump/a9_recovery/bootstrap_device1.jsonl` 仅有六个 a9 provider 进入/退出事件。
它能解释 a9 密钥派生初始化，不能作为 a7/a8 生成路径的直接证据。

当前日期布局要求毫秒时间为 11 位 hex。超出该范围时，模块明确拒绝，未模拟原生 hexString2Byte
对奇数长度文本的截断行为。服务端接受新的整组画像、A envelope 和完整注册成功仍需要独立验证。
