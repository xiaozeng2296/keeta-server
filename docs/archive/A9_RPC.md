# a9 离线 RPC

`keeta_rpc.py` 的 `/a9/decode`、`/a9/encode` 和 `/decrypt` 已使用 `mtgsig.a9_codec`，不依赖 `v73.bin`。本次验证直接调用 Python 操作函数，没有启动服务或发送网络请求。

所有请求必须提供生成该 a9 时的原始 `a1`。`/a9/decode` 需要明确指定 `profile`；`/decrypt` 直接接收完整 mtgsig 且省略 `profile` 时，会严格尝试本版本已验证的 `default`、`legacy` 两套配置，并在响应中返回实际命中的配置。显式指定 `profile` 或覆盖参数后不会回退。`legacy` 读取项目固定文件 `mtgsig/a9_legacy_profile.json`；API 不接受文件路径作为 profile。

解密请求：

```json
{
  "a9": "<完整 a9>",
  "a1": "<原始 UUID>",
  "profile": "legacy",
  "mode": "auto"
}
```

发送到 `POST /a9/decode`。默认 `mode=auto` 只在指定配置下识别 `aes`、`twofish`、`twofish-mod`，使用严格填充、CRC32 和完整 zlib 校验；不会猜测其他身份或配置。成功响应以 `plain_json` 返回原始对象/数组，并同时返回 `plain_explained` 可读解释；另含实际 `mode`、所选 `profile` 和 `a1_shift`。JSON 明文成功时不再默认返回重复的 `plain_b64` 或 `plain_text`。

加密请求发送到 `POST /a9/encode`：

```json
{
  "a1": "00112233-4455-6677-8899-aabbccddeeff",
  "profile": "default",
  "mode": "twofish-mod",
  "siua_json": {"0": 12, "1": ["synthetic"], "2": [], "3": "{}"}
}
```

加密必须明确指定三个算法之一，不能用 `auto`。`siua_json` 可为字符串、对象或数组；字符串保留原始字节表达，对象和数组用紧凑 JSON 序列化。响应包含 `a9`、`mode`、`profile` 和 `a1_shift`。算法和配置必须与目标 SDK 状态匹配；能加解密不表示该采集内容会被服务端接受。

也可将完整头直接交给 `POST /decrypt`，无需 `mtgsig` 外层包装：

```sh
curl -H 'Content-Type: application/json' --data-binary @mtgsig.json http://127.0.0.1:8799/decrypt
```

也支持 `{"mtgsig": ...}` 包装和 JSON 字符串。结果位于 `fields.<field>`；能解出的字段返回 `decryptable=true`、`plain_json` 和 `plain_explained`，失败时 `decryptable=false` 并给出错误，不返回未经验证的明文。外层若另给 a1，必须与头内值一致。其他签名字段的处理没有改动。

## 响应中的正常值和解释值

`plain_json` 是解密后的原始 JSON 结构，适合程序继续处理。例如，a9 的正常值保留 SDK 使用的数字键和数组顺序：

```json
{
  "plain_json": {
    "0": 12,
    "1": [0, "WiFi", 0, [5, 100], "Darwin"],
    "2": [0, 1790055550727.318, 127933894656, {"33": {"0": 0}}],
    "3": {"253": 5, "127": 5}
  }
}
```

`plain_explained` 是同一份数据的可读投影。根节点统一为 `{"fields": [...]}`，每个字段包含 `key`、`name`、`value`；嵌套 JSON 会继续放在 `fields`，a9 的两个数组字段会在对应节点下增加 `items`。它不改变或重排 `plain_json`，并在数组项中保留原始 `index`，因此可以在两种视图之间逐项对照。a9 的结构如下：

```json
{
  "plain_explained": {
    "fields": [
      {"key": "0", "name": "schema 版本/项数", "value": 12},
      {
        "key": "1", "name": "基础设备字段(16项)",
        "value": [0, "WiFi", 0, [5, 100], "Darwin"],
        "items": [
          {"index": 0, "name": "标志", "value": 0},
          {"index": 1, "name": "网络类型", "value": "WiFi"},
          {"index": 2, "name": "浮点占位", "value": 0},
          {"index": 3, "name": "常量数组", "value": [5, 100]},
          {"index": 4, "name": "系统名", "value": "Darwin"}
        ]
      },
      {
        "key": "2", "name": "扩展设备字段(23项)",
        "value": [0, 1790055550727.318, 127933894656, {"33": {"0": 0}}],
        "items": [
          {"index": 0, "name": "标志", "value": 0},
          {"index": 1, "name": "系统启动绝对时间(毫秒)", "value": 1790055550727.318},
          {"index": 2, "name": "磁盘总量", "value": 127933894656},
          {"index": 3, "name": "环境检测对象", "value": {"33": {"0": 0}}}
        ]
      },
      {"key": "3", "name": "采集来源/耗时码映射", "value": {"253": 5, "127": 5}}
    ]
  }
}
```

数组索引从 `0` 开始，与 `plain_json["1"]` 或 `plain_json["2"]` 的实际下标一致。当前已知的 a9 基础项和扩展项含义见 [`V5_SIGN_FIELDS.md`](root/V5_SIGN_FIELDS.md) 的 a9 表；未知或仅作占位的项仍会保留为 `index`，不会根据值猜测含义。解释是展示辅助信息，程序应以 `plain_json` 的原始值为准。

a5 的解释视图也使用 `fields` 列表。顶层 `b*` 字段及 `b1` 内层字段都带 `key`、`name`、`value`；如果原值本身是 JSON 字符串，节点额外保留 `raw`，解析后的子对象放在 `fields`，例如：

```json
{
  "plain_json": {
    "b2": 6,
    "b3": 1,
    "b4": "com.sankuai.sailor.ifooddelivery",
    "b16": "[0,0,0],[1,1,0],[0,0,0],0"
  },
  "plain_explained": {
    "fields": [
      {"key": "b2", "name": "签名序号", "value": 6},
      {"key": "b3", "name": "a5 采集序号", "value": 1},
      {"key": "b4", "name": "应用包名(bundleId)", "value": "com.sankuai.sailor.ifooddelivery"},
      {"key": "b16", "name": "传感器采样序列", "value": "[0,0,0],[1,1,0],[0,0,0],0"},
      {
        "key": "b1", "name": "设备指纹主体",
        "value": {"0": 23, "2": "WiFi"},
        "raw": "{\"0\":23,\"2\":\"WiFi\"}",
        "fields": [
          {"key": "0", "name": "设备属性槽 0", "value": 23},
          {"key": "2", "name": "设备属性槽 2", "value": "WiFi"}
        ]
      }
    ]
  }
}
```

`fields.a5`、`fields.a9` 和 `/a5/decrypt`、`/a9/decode` 均使用这两个明文键名。`plain_json` 不是字符串化 JSON；若明文是合法 UTF-8 但不是 JSON，响应改用 `plain_value` 返回字符串，并不会伪造 `plain_explained`。无法按 UTF-8 解码的二进制只返回 `plain_bytes_len`，不会把二进制复制成 base64 或文本。服务不再默认返回重复的 `plain_b64`、`plain_text` 或 `plain_text_lenient`。

### a9 数组索引速查

下表中的 `index` 就是 `plain_json["1"][index]` 或 `plain_json["2"][index]` 的下标，解释响应会把它原样带回：

| 数组 | index | 含义 |
|------|------:|------|
| `1` 基础 | 0 | 标志 |
| `1` 基础 | 1 | 网络类型 |
| `1` 基础 | 2 | 浮点占位 |
| `1` 基础 | 3 | 常量数组（常见为 `[5,100]`） |
| `1` 基础 | 4 | 系统名 |
| `1` 基础 | 5 | 厂商 |
| `1` 基础 | 6 | 运营商名 |
| `1` 基础 | 7 | iOS 版本串 |
| `1` 基础 | 8 | 主板型号 |
| `1` 基础 | 9 | 语言 |
| `1` 基础 | 10 | 设备类小写 |
| `1` 基础 | 11 | 设备类 |
| `1` 基础 | 12 | 时区 |
| `1` 基础 | 13 | 屏幕分辨率 |
| `1` 基础 | 14 | 内核大版本 |
| `1` 基础 | 15 | 占位 |
| `2` 扩展 | 0 | 标志 |
| `2` 扩展 | 1 | 系统启动绝对时间（毫秒） |
| `2` 扩展 | 2 | 磁盘总量 |
| `2` 扩展 | 3 | 环境检测对象 |
| `2` 扩展 | 4 | 电池电量 |
| `2` 扩展 | 5 | 亮度/电池值 |
| `2` 扩展 | 6 | Bundle ID |
| `2` 扩展 | 7 | SDK/App 版本 |
| `2` 扩展 | 8 | 可用磁盘（实时） |
| `2` 扩展 | 9 | 当前墙钟（毫秒） |
| `2` 扩展 | 10 | 设备指纹 hash / csecuuid |
| `2` 扩展 | 11 | 物理内存（`hw.memsize`） |
| `2` 扩展 | 12 | 空数组/预留 |
| `2` 扩展 | 13 | 标志 |
| `2` 扩展 | 14 | 标志 |
| `2` 扩展 | 15 | 标志 |
| `2` 扩展 | 16 | 会话 nonce |
| `2` 扩展 | 17 | 占位（常见为 `unknown`） |
| `2` 扩展 | 18 | 机型 |
| `2` 扩展 | 19 | 占位 |
| `2` 扩展 | 20 | 渠道 |
| `2` 扩展 | 21 | 内核 boottime |
| `2` 扩展 | 22 | 进程启动时间戳 |

这些是当前已验证 SDK 的展示名称，不是密码学字段名。新 SDK 可能增加或调整数组项；此时服务仍返回原始 `index` 和 `value`，未知项会标注为占位/未知，不会丢弃。

以上三个入口均接受显式覆盖 `salt_hex`（16 字节盐）、`k3_hex`（至少 10 字节）、`a1_shift`（0 至 35 的整数）。覆盖所选 profile 时，响应会用 `profile_overrides` 列出覆盖字段名。未知配置应从对应版本的实际初始化资料确定，不能默认套用历史配置。

`GET /health` 中 `a9_ready=true`、`a9_requires_v73=false`；旧的 `v73_present` 仅保留为表文件状态，不影响这三个 a9 入口。

离线测试：

```bash
python3 -m unittest discover -s tests -p 'test_a9_rpc.py'
```
