# m-series 字段变换

> 历史研究资料，来源 `codex/keeta-project@6197c528`；保留当时的观测与未完成项，不代表新项目当前状态。当前规则见 [字段状态](../MTGSIG_FIELDS_STATUS.md)，复跑入口及已修正结论见 [离线研究指南](../research/OFFLINE_RESEARCH.md)。文中的旧 `dump/`、抓包及设备路径仅作证据索引，原材料未随仓库发布。

`mtgsig/corpse_codec.py` 实现 Keeta iOS 3.12.401 / SAKGuard 5.21.10 的 m-series 字段变换。
固定表决定每个字段的 shift，不需要猜测。包括曾出现歧义的 m137 在内，原始 126 字段
JSON 可以完整解码、重新编码，逐字节还原 26972 字节，不需要豁免字段。

## 算法与原生边界

正确核心为 `K+0x38d334..0x38d544`，表在 `K+0x333c094`（256 个 uint32）：

```text
shift = table[field_number % 256]
byte ∈ [32,125]  →  (byte - 32 + shift) % 94 + 32
其余字节         →  原样
```

这里包括空格，不包括 `~`；`~`、DEL、其他控制字节和 UTF-8 高位字节均保留。
因此空格与 `~` 不碰撞，变换完全可逆。原生输入以 C 字符串传递，所以接口拒绝 NUL；
合法输入的编码也不会产生 NUL。模块拒绝非字符串值和不能编码成 UTF-8 的孤立代理字符。

旧工具的 `33..126` 猜 shift 不准确。恢复的表给 `m260` shift=81、`m321` shift=76，
与旧启发式结果 82、25 不同。旧 `corpse_v5sign_127.json` 不能作为全部字段的已验证明文。

## 真实整对象调用链

- `K+0x2fc80c` 用字段编号构造 `mN`，再调用 `K+0x2dec2c` 添加到 cJSON 对象。
- `K+0x2fc948` 的第 4 个参数控制是否进行字段变换。mode=1 才调用与
  `K+0x2fc8c0` 相同的 VM（字节码 `K+0x330d544`，长度 `0x640`）；mode=0
  在 `0x2fd3cc` 直接跳到 `0x2fd204` 打印缓存原值。当前 sign/info 的 mode=0
  输出不可再传 `decode_fields`，否则会把原值再次偏移成乱码。
- 新核心函数指针位于 `K+0x405f140`，是该 VM 使用的 `K+0x405edd0` 外部函数表第 110 项。
- 新核心 ABI：`x0=const std::string*`、`w1=field_number`、`x8=24B std::string*` 隐藏返回对象。

`tools/corpse_wrapper_probe.py` 已在正常运行进程内对整对象入口直接调用：
`2dee3c` 建合成 cJSON → `2dec2c` 添加字段 → `2fc8c0` 完整 VM 变换 → `2dddcc` 输出 JSON。
字段为 m3/m137/m260/m321，三组输入覆盖普通字符串、空格/`~`、ASCII 1..127、中文/emoji、空值。
**三组整对象输出全部与 Python 逐字段及 JSON 字节匹配，输入对象全部保持不变。**
这确认 m137 使用同一变换，不需要猜后处理，也不依赖从密文猜明文的循环验证。

实验仅 attach，先校验函数代码字节；没有 hook、重启、reset 或业务网络请求。
新对象和序列化缓冲按 SDK 析构器/配置的 allocator 释放，完成后 session 已 detach。
证据：`dump/corpse_recovery/native_wrapper_01.json`；发布 fixture 只保存合成输入输出。

## 使用

```python
from mtgsig.corpse_codec import encode_field, decode_field, encode_fields, decode_fields, encode_json

assert encode_field("Keeta", 3) == "Iccr_"
wire_fields = encode_fields({"m3": "Keeta", "m137": "Synthetic kernel~1"})
assert decode_fields(wire_fields)["m137"] == "Synthetic kernel~1"
raw_json = encode_json({"m3": "Keeta", "m137": "Synthetic kernel~1"})
```

嵌套 JSON 仍由调用方明确序列化成字符串。字典顺序保留，字段名要求规范的 `mN`。
可通过显式 `passthrough=("m137",)` 原样保留调用方已编码的字段，但 m137 本身不再需要
这个选项；没有任何默认豁免。未知 SDK 版本不据此自动兼容。

## 验证

`tools/verify_corpse_codec.py` 在 Unicorn 中执行新核心原始 ARM64 指令及分发表，只模拟
两个标准库操作 `std::string::at/push_back`。覆盖全部 256 个表项、9 个其他字段编号、
ASCII 1..127、中文/emoji、空串及不同长度，共 270 组均与 Python 精确匹配。
合成向量与三组原生整对象向量存 `tests/fixtures/corpse_native_vectors.json`。

手机原生直接调用 `dump/corpse_recovery/native_core_comparison_01.json` 对两个核心
分别使用字段 3/137/260/321 和三组合成边界文本，共 24/24 匹配各自语义。
新核心原生保留 `~`，不是模拟器或 Python 人为修正。

```bash
PYTHONPATH=/tmp/keeta_a9_deps python3 tools/verify_corpse_codec.py
python3 -m unittest discover -s tests -p test_corpse_codec.py -v
```

真实 `corpse_v5sign_raw_obf.bin` 中的 m137 完整恢复
`Darwin Kernel Version ... root:xnu-8792.62.2~1/RELEASE_ARM64_T8030`，原来的 `O1` 误解消失。
新核心同样解释两机 `/tmp/dual/*corpse.bin` 和历史 envelope 明文中的波浪号。
这些验证证明字段变换及序列化，不证明设备画像语义或服务端注册成功。

`current_registration_payloads_01.json` 的旧 `plain_fields` 是采样后误解码所得，
不可用作画像输入；`field_roundtrip_match` 只证明可逆循环，并无语义证明。
原证据保留，更正派生件为 `dump/envelope_recovery/current_registration_payloads_01.corrected.json`，
其 `cache_fields` 直接解析原始 `prepared_text`，同时记录 `prepare_mode=0`。

## 早期候选为何不对

最初定位的 `K+0x2ef840` 使用另一份内容完全相同的表，却处理 `32..126`，会把 `~`
与空格合并。它自身的静态模拟及原生调用都没有错，错的是将它认作当前 m-series 入口。
只读复核确认该核心 544B 与文件一致，也排除了运行时改指令。m137 的真实样本促使继续
查找，最终找到正确的 `0x38d334` 边界，并以整对象原生调用确认。

旧核心模拟结果独立保存在 `dump/corpse_recovery/2ef840_native_vectors.json`，展开汇编
保存在同目录。旧笔记里的 `sub_100791634` 只是共用函数尾部，`d5fB4mkd:` 是另一条
`NSJSONSerialization → CCCrypt → Base64 → fingerprint/Baal` 路径。
