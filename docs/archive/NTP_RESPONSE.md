# FAMA /ntp A 响应与历史 DFP 缓存

> 历史研究资料，来源 `codex/keeta-project@6197c528`；保留当时的观测与未完成项，不代表新项目当前状态。当前规则见 [字段状态](../MTGSIG_FIELDS_STATUS.md)，复跑入口及已修正结论见 [离线研究指南](../research/OFFLINE_RESEARCH.md)。文中的旧 `dump/`、抓包及设备路径仅作证据索引，原材料未随仓库发布。

`/ntp` 是独立的 FAMA 协议，不是 `/v5/sign` 的同名响应，也不是 `/v1/scfg`。
此前 20 节点注册模板遗漏这类请求；当前响应状态机已接入独立 `/ntp` 分支。
下面结论来自当前 `dump/Keeta.dec` 的指令、4 条既有抓包响应
及后续 mtgsig 的离线对拍；本轮没有操作手机、发送网络请求或写 Keychain。

## 响应形态与转换

已观察的 `/ntp` HTTP 200 响应是顶层对象：

```text
status: 0 (integer)
message: string
version: "1.0"
ts: integer
ntp_info: standard Base64, decoding to 28 bytes
ab_test_flag: "A"
interval: 24 (integer hours)
```

同会话 `/v5/sign` 的 A 回执则为 `code=0` 下的 `data` 对象，包含
`ab_test_flag/serverTimestamp/clientIp/interval/dfp`，没有 `ntp_info/ts`。
不能把这个 data 对象直接送入 NTP 解码器。

`0x389004` callback 的 x1 参数保存在 x24，后续直接对它取字段，没有再取一层 data。
非错误字符串路径中，`0x3893c4` 在 `ab_test_flag == "B"` 时绕过此写入分支；
A 进入下列转换：

| 指令位置（K 相对 RVA） | 数据流 |
|---|---|
| `0x3893ec..0x389454` | 读取 x24[ntp_info]，NSData `initWithBase64EncodedString:options:1` |
| `0x389464..0x3894fc` | 读取 x24[ts]，`%@` 转字符串，`longLongValue`，REV 后存成 8 字节大端数据 |
| `0x389554..0x38958c` | 对 Base64 字节逐项 XOR，索引为 `(i OR -4)+8 = 4+(i&3)` |
| `0x3895b4` | 调 `0x3904d0(bytes,length)`，逐字节 `%02x`，生成小写十六进制 DFP |
| `0x389708..0x389750` | 读取 interval 的 intValue；`0x32648c` 按 interval×3600 秒计算过期时间并保存 |
| `0x389778..0x389780` | 检查生成的字符串非空；为空时跳过 fingerprintData 写入 |
| `0x389800..0x38992c` | 构建五项字典，详见下文 |
| `0x389958..0x389974` | `SAKGuardLocalIDKeychainStorage addKeychainData:forKey:"fingerprintData"` |
| `0x389978..0x389984` | 另经 `0x364e98` 保存 `sakguard_storage_dfpid`，值为同一个解码字符串 |
| `0x389a14 → 0x3892fc..0x389310` | 释放临时数据后，通过捕获的完成 block 返回该解码字符串 |

等价转换为：

```python
payload = base64.b64decode(response["ntp_info"])
mask = (response["ts"] & 0xffffffff).to_bytes(4, "big")
dfp = bytes(value ^ mask[i & 3] for i, value in enumerate(payload)).hex()
```

这里不需要 AES 密钥、设备上的 16 字节材料或服务端额外下发密钥。
28 字节输入产生 56 字符 DFP。`0x3904d0` 是十六进制格式化，不是另一个分组密码。

实际写入 fingerprintData 的形态：

```text
serverTimestamp: decimal string of response.ts
interval: decimal string of response.interval
dfp: decoded lowercase hex string
ab_test_flag: response.ab_test_flag
version: response.version, or empty string when native sees nil
```

`0x364e98` 进一步调用 `SAKGuardDCDeviceInfo.sharedManager.storage`
的 `setString:forKey:userDefaultsSuiteName:`。它是额外 SDK 存储，不能与前面的 Keychain setter 混称。

字符串来源不是仅凭命中搜索：对应函数起始处 `0x2dd248` 解混淆调用的 src/seed/length
与 CFString 引用逐项对应；`0x4cbcc10`→ntp_info、`0x4cbcc50`→ts、
`0x4cbcc70`→interval、`0x4cbccf0`→dfp。`0x3904d0` 的格式串从
`src=0x333f98c, seed=0x5e, length=4` 解得 `%02x`，并由逐字节格式化循环消费。

## 抓包关联与路由

以下索引均为零基。4 条响应都为 HTTP 200/status 0/A/1.0，解码结果都与同会话
`/v5/sign data.dfp` 相等，并在后续 mtgsig.a8 中出现。测试只输出布尔断言，不泄露标识值。

| 抓包与索引 | 实际 authority/path | 结果关联 |
|---|---|---|
| 完整版新设备注册登录 #15 | poke.mykeeta.com/ntp | 等于 #36、#132 v5/sign DFP；#47 起后续签名使用同一 a8 |
| 完整版新设备注册登录 #131 | poke-eu.mykeeta.com/ntp | 与 #15 相同；后续 a8 持续一致 |
| 新机之后尝试登录 #20 | poke.mykeeta.com/ntp | 等于 #16 v5/sign DFP；#41 起后续 a8 一致 |
| 从app初次打开到登录被拦截 #95 | poke.mykeeta.com/ntp | 等于 #100 v5/sign DFP；该采集中此前已有同一 a8 |

**完整成功包 #131 的 Charles 顶层 host 是 fooddelivery-eu.mykeeta.com，而实际 HTTP/2
`:authority` 为 poke-eu.mykeeta.com。构建请求必须使用 authority，不能把顶层 host 当成业务路由。**

完整包 #15 的 NTP 响应先完成，#36 的 v5/sign 后完成，首条观察到目标 a8 的 #47 紧随 v5/sign。
因此抓包的先后与值相等只证明一致性，不能单独将 a8 的首次更新时间归因于其中某一个 callback。
Keychain 写入的直接证据仍来自上述非 B 分支指令及上游 callback 绑定。

## 独立实现与严格边界

`mtgsig/ntp_protocol.py` 提供：

```python
decoded = decode_ntp_response(response, http_status=actual_status)
patch = decoded.identity_patch()
cache = decoded.fingerprint_data()
```

`patch` 包含 `a8/a8_server_dfp/dfp/outid_history_dfp`；调用者负责把真实响应关联到当前请求、
保存来源并显式应用状态。decoder 不修改 identity、不写文件、不发送请求。

`registration_state.parse_registration_response()` 已按精确 `/ntp` 路径调用此 decoder，
返回上述 patch，并携带 `ntp_fingerprint_data` 五项字典和 `ntp_response_source`。
`apply_registration_response()` 在完整校验之后更新同一会话，保留已有 local 别名；
FullSigner 复用此入口同步后续 a8。非法响应返回空 patch，不改变身份。

`fresh_device_profile.prepare_profile()` 可消费当前 context 中唯一的 ntp row，要求
`prepare_mode=0` 和精确的 24 项 FAMA ID 列表；它保留原生聚合及 checksum 上下文，
不将 device-info 的 mode1 当成 NTP 编码。该支持不等于旧 context 自动获得原生 NTP
输入，也不证明真实网络流程已跑通。原生已完成注册的单账号登录无需为验证此模块重跑注册。

当前只支持已观察的完整 A/1.0：HTTP 2xx、整型 status=0、正 signed-int64 ts、
不会溢出原生 interval×3600 的非负整型小时、canonical Base64 的 28 字节 ntp_info。
布尔值不会当整数接受。B、缺字段、未知版本、非 canonical 或异长密文均明确拒绝。
原生允许 Base64 IgnoreUnknownCharacters，且对部分 nil 值有默认行为；这里刻意不宽松复刻，
以免异常响应被持久化成设备身份。未知版本需要新的证据后再扩展。

8 项离线测试涵盖独立合成向量、低 32 位语义、HTTP/业务/类型/编码校验、输入不突变、
原生五项字典结构，以及以上 4 条真实 capture 与后续 a8 的对拍：

```bash
python3 -m unittest discover -s tests -p test_ntp_protocol.py
```
