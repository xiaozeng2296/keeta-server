# `/v1/scfg` 来源与离线处理

> 历史研究资料，来源 `codex/keeta-project@6197c528`；保留当时的观测与未完成项，不代表新项目当前状态。当前规则见 [字段状态](../MTGSIG_FIELDS_STATUS.md)，复跑入口及已修正结论见 [离线研究指南](../research/OFFLINE_RESEARCH.md)。文中的旧 `dump/`、抓包及设备路径仅作证据索引，原材料未随仓库发布。

当前版本的 `scfg` 是独立配置协议。它没有使用 A-envelope 的分隔符或字段布局。

## 请求

真正的请求路由是 `handle:data:rCount:sr:completion:` 的 enum 4，分支
`0x31dab8`，路径字符串 `/v1/scfg`。请求在 `0x3245a4` 构造，先序列化字段对象，
调用 `+[SAKGuardCommon encrypt:]`（内部 `NativeBridge call:withParam:`，参数包含
`aesKey`，操作码 2），再用 Base64 放入外层 JSON：

```json
{"data":"<base64>","os":"iOS","mtg_version":"<SDK version>"}
```

内层字段及静态来源：

| 字段 | 来源 |
| --- | --- |
| `os_version` | `UIDevice.systemVersion` |
| `package` | m154 |
| `package_version_code` | m144 |
| `timestamp` | 当前 Unix 毫秒字符串，`%0.f` |
| `dfpid` | `SAKGuardDeviceFingerprint.getFingerprintID` |
| `uuid` | m153 |
| `userid` | `SAKEnvironment.user.userID.intValue`；nil 时原生为 `-1` |
| `city` | `SAKEnvironment.city.name` |
| `dpid` | m136 |

`0x324d28` 是 `+[SAKGuardCommon encrypt:]` 的调用点；加密实现与本地 XID 使用相同
固定 AES-128-CBC/PKCS7 profile：`DEFAULT_LOCAL_XID_PROFILE` 的 key/IV。已对两份真实
请求（索引 244、464）解密，明文均为 303 字节、上述九个字段。

## 响应与状态

只读取 `response.data.resStr`。顶层 `response.resStr` 为空字符串，不能混用。
该字段经过同一 AES-CBC profile 解密为：

```json
{"private_key_config":"","applist_config":"","version_code":"1"}
```

回调先清除 `applistOpen`；只有 `applist_config == "221"` 才重新设为 1。
`private_key_config` 按 `|` 分割并追加到 `privateCollectArr`，因此空字符串在当前样本中
会产生一个空成员。`version_code`、`serverTimestamp`、`clientIp`、`interval` 在该回调
路径没有观察到消费，不应凭字段名写入其他状态。

## 实现与验证

- `mtgsig/scfg.py`：`build_scfg_request`、`encode_scfg_data`、`decode_scfg_data`、
  `parse_scfg_response`。
- `tests/test_scfg.py`：真实两次请求/响应、精确 JSON 重加密、错误路径测试。

离线测试：

```sh
python3 -m unittest tests.test_scfg
```

该模块不访问手机、网络或 keychain；它只使用已恢复的版本化本地 AES profile。

主流程接入见 [REGISTRATION_FLOW](REGISTRATION_FLOW.md)：`scfg_inputs` 提供设备/SDK环境，当前
OneID、a8和毫秒时间由本次请求状态绑定，解密配置在发送后回填。缺输入或无效响应
都会阻止后续请求；不会复用旧 data。此接入目前完成禁网序列验证，真实发送另以
`dump/registration_session/` 的响应记录为准。
