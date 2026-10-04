# m175 的采集来源与离线加解密

> 历史研究资料，来源 `codex/keeta-project@6197c528`；保留当时的观测与未完成项，不代表新项目当前状态。当前规则见 [字段状态](../MTGSIG_FIELDS_STATUS.md)，复跑入口及已修正结论见 [离线研究指南](../research/OFFLINE_RESEARCH.md)。文中的旧 `dump/`、抓包及设备路径仅作证据索引，原材料未随仓库发布。

`m175` 已从当前二进制还原，并以原 ARM64 指令及两份不同真实缓存完成双向验证。
它不是服务端下发的身份密文，可以用明确的设备配置及采集时间独立生成。

适用样本：`dump/Keeta.dec`，SHA256
`0900cac89f75fc4f75279c708785bf2c7a03c228301a8e75ce62f93e3ad88488`。
下列地址均为 RVA（Mach-O 基址 `0x100000000`），读文件须按段映射。

## 采集链

`0x34eaa4` dispatcher 的表 `0x350e8c[(175-122)]` → 分支 `0x34eef4`
→ `0x348714..0x349958` collector。collector 构造两份 JSON，直接拼接为 UTF-8 文本：

| JSON 字段 | 来源 | 证据 |
| --- | --- | --- |
| 第一份 `a`、第二份 `n` | 原值 m166：硬件型号 | collector `0x34a508` 解出 `hw.machine`，经 `0x364034` 读取 |
| 第一份 `b`、第二份 `r` | 当前毫秒时间的十进制字符串 | `NSDate.timeIntervalSince1970 * 1000`，`%.0lf` |
| 第二份 `m` | `UIDevice.currentDevice.name`（m151 的采集来源） | dispatch `0x34f594` → `0x3484c0` 读取 name，`0x348544` 赋值给 monitor 的 deviceAccount；nil 回退 `unknown` |
| 第二份 `o` | 原值 m160：系统名称拼接系统版本 | `0x35b6c4` 的 systemName/systemVersion，`%@%@` |
| 第二份 `p` | 原值 m19：布尔检测结果字符串 | `0x354f90` → `0x36ef70` → VM，返回值 `& 1`；检测含义尚未命名，不能当恒定 0 |
| 第二份 `q` | 原值 m167：屏幕像素宽高 | `0x349958`，UIScreen.bounds × scale 后转整数、按 `%d*%d` 拼接 |

`0x351458` 重新调用对应 collector，再经 `0x385a24` 提取返回包装中的值。
当前缓存为 prepare_mode=0，`prepared_text` 直接 `json.loads` 即原字段，**不能再次 decode_fields**。

`deviceAccount` 属性名称容易误导：这里实际储存设备名称，不是服务器账户、令牌或登录会话。
该 collector 的输入链未读取 m11/m293/a7/a8。两份真实缓存解出的 n/o/p/q 与
同份原缓存 m166/m160/m19/m167 均一致；真正依据是静态赋值链与变换验证，不能仅凭明文搜索推断无依赖。

## 完整变换

令 `P` 为两份 JSON 连续拼接的 UTF-8 字节：

1. 标准 MD5(P) 的 4 个小端 32-bit 字按 `C,A,D,B` 输出，转大写 hex，得 32 字符 `D`。
2. CRC32(P) 按 `%016u` 输出，即宽度 16、前补零的**十进制**字符串 `C`。
3. 构造 `B = b"AI" + D + C + P`，整体再转大写 hex ASCII。
4. 不足 16 字节时用字节 `0x5e`（`^`）补齐；已对齐则不增加填充块。
5. Twofish MDS 变体（常量 `0xBC`）ECB，固定 16-byte key，在 collector 内由短常量拼接。
6. 最终密文转大写 hex 即 m175。

关键实现 RVA：MD5 `0x2ee960/0x2ee980/0x2ef67c`（字序改变发生在 final 输出）；
CRC `0x2e83d4`；hex `0x2f0440`；ECB 包装 `0x2f00b0`；
Twofish 初始化/扩展/块加密 `0x39361c/0x3937f0/0x3941ec`。
ECB 包装从 `0x3305e28` 取 `[0,0xBC]`，因此无需根据块长猜算法。

旧的「32-byte AES key + PKCS7」假设不适用于此链。

## 接口

`mtgsig/m175_codec.py`：

```python
from mtgsig.m175_codec import encode_m175, decode_m175, encode_payload

m175 = encode_m175(
    model="iPhone12,1",              # 原 m166
    system_version="iOS16.2",        # 原 m160
    field19="0",                    # 已确定的原 m19；这里仅是合成示例
    screen="828*1792",               # 原 m167，保持实际格式
    device_name="Synthetic iPhone",  # 所选设备配置的名称
    timestamp_ms=1700000000123,
)
decoded = decode_m175(m175)
assert encode_payload(decoded.payload) == m175
```

`encode_m175` 接受已取整的毫秒时间；若复现 NSDate 浮点到字符串的边界舍入，应由调用方完成。
`encode_payload` 保留原 JSON 的排序、空格和转义，可精确复现捕获密文。
`encode_m175` 为新输入构造有效 JSON；NSDictionary 的键迭代顺序不是稳定协议约定，
不承诺任意设备上对相同字段重序列化得到同一字节串。

## 验证与边界

```sh
PYTHONPATH=/tmp/keeta_a9_deps python3 tools/verify_m175.py
python3 -m unittest tests.test_m175_codec
```

验证器不访问手机或网络。仅提供内存/分配函数和栈保护存储，运行未经修改的原生 MD5、CRC、
Twofish 及 ECB/填充包装。覆盖 15 种长度（0/1/15/16/17、MD5 55/56/63/64/65 边界等）、
5 组设备配置（含 Unicode、nil 名称），并验证两份不同的 352B 真实 m175 精确重加密。
报告 `dump/m175_recovery/verification.json` 不包含真实字段值；合成向量位于
`tests/fixtures/m175_vectors.json`。完整分析汇编保存在 `dump/m175_recovery/`。

密码模块本身未做服务器接受性测试。
上层 `registration_payloads.render_envelope_plaintext` 可选 `derive_m175=True`：先应用 bindings，
再使用显式 `state.device_name`、`state.timestamp_ms` 与原值 m166/m160/m19/m167 生成 m175，
之后计算 m320 和执行字段 transform。该选项不改写原捕获文件；设备名应与所选 profile 的 m151 一致。
集成时应使用当前配置的 m166/m160/m19/m167/设备名称与选定采集时间，生成 m175 后再更新上层 m320，
不能将旧 m175 直接跨设备复用，也不能把通过离线原指令对拍等同于任意 SDK 版本通用。
