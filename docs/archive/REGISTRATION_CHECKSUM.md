# 注册明文中的 m320

> 历史研究资料，来源 `codex/keeta-project@6197c528`；保留当时的观测与未完成项，不代表新项目当前状态。当前规则见 [字段状态](../MTGSIG_FIELDS_STATUS.md)，复跑入口及已修正结论见 [离线研究指南](../research/OFFLINE_RESEARCH.md)。文中的旧 `dump/`、抓包及设备路径仅作证据索引，原材料未随仓库发布。

`mtgsig/registration_checksum.py` 实现当前镜像的健康 SDK 分支。它计算注册 A payload 的 m320；与 mtgsig.a2 是不同层，修改 m27/m153 等字段后必须重算。

## 输入与算法

API：`compute_m320(fields, appkey=..., version=..., sdk_flag=..., provider_mask=...)`。

- fields 是当前 route 在变换前的原始字符串对象。唯一键接口 `compute_m320` 删除旧 m320 后重算；按字段名词典序把每个 name 与 value 的 UTF-8 字节直接连接，没有 JSON 标点。
- appkey 来自 `0x2fe2d8`；当前已采样上下文中与 mtgsig.a1相同。
- version 参数接收 `0x316ca0` 查内部 `a0` 返回的完整字符串。当前64B值不是 mtgsig.a0 的 `2.5`，也不是 SDK release，不能替换为 b10。
- sdk_flag 是 `int32[K+0x4e45570]`，当前上下文名为 cipher_flag；不是 `byte[K+0x4d3a1ac]`。
- provider_mask 是 provider 对象开头16B，不是 envelope 的随机会话 key。

同一个 `cipher_flag` 也控制 A-envelope 密码模式：`0x2fc654` 读取
`K+0x4e45570`，取有符号 `% 3`；非负余数 0 对应 Twofish-mod，1 对应
Twofish，2 对应 AES。当前上下文的 186 与同次 mtgsig.a10 第二项相同，
因此选 Twofish-mod；先前 250 对应 Twofish。这是算法选择参数，不是
逐请求递增的 a5.b2。静态分支与 wrapper 证据见
`dump/envelope_recovery/BUILDER_ENTRY.md`。

`0x38dc2c` 创建 appkey 长度的 HMAC key：遍历 `max(len(appkey),len(config_a0))`，将 `appkey[j] XOR config_a0[i % config_len] XOR (sdk_flag &255)` 写入 `key[j]`，j=i%appkey_len。当配置更长时后写覆盖前写。当前64B配置没有先做 base64 解码；原 VM 的实际HMAC key逐字节证实这一点。

之后：HMAC-SHA1 → 用固定16B key进行 AES-128-ECB → 取首16B。每字节执行 `((aes[i]+hmac[i]) &255) XOR mix[i] XOR provider_mask[i]`；**最后一个结果字节清最低位**。最终输出该16B的 Adler32 无符号十进制字符串。固定 AES key与混合常量保留在实现中。

最后清位发生在与 provider_mask 异或之后。只清加法结果最低位会在 mask[15] 为偶数时失败；“按消息长度奇偶调整”也是已撤销的假设。

## 真实入口与顺序

`0x2fc910` 是 std::string 隐藏返回 ABI，x0为 cJSON、x8为24B返回对象；VM程序 `0x330db84`，长度 `0x10d8`。它调用 `0x2dfbd0` 对字段排序，随后 `0x38d5f4` 完成密码派生，最终 `adler32` 和 `%lld` 格式化。

共同 collector `0x2fc948` 先计算 m320，随后在 mode1 才做 m-series变换。mode0直接序列化原值。故离线顺序是更新设备字段 → 重算 m320 → 可选 encode_fields → envelope → mtgsig签名。

`0x2fc948` 在 `0x2fd37c..0x2fd398` 直接调用同一个 VM 程序，**不经过**
`0x2fc910` 包装器。因此仅 hook 后者观察不到 collector checksum，不能据此认定
device-info 使用另一个算法。

## device-info 全缓存与重复键

全 `0..599` 的 mode0 诊断输出包含 402 个 cJSON 节点、400 个唯一键：
缓存的空 m307、空 m320 各占一个节点，末尾再追加聚合 m306、状态 m307、新 m320。
普通 `json.loads` 会覆盖早先同名字段，丢失 checksum 的实际输入。

`compute_m320_pairs` 接收**新 m320 追加之前**的完整有序键值对，不自动排除同名
m320。原生排序保留重复节点，字段名相同时反转插入顺序。因此旧的空 m320 仍贡献
`b"m320"`，新的状态 m307 与旧的空 m307 都参与 HMAC。原 VM 已验证 2、3、4 个
重复节点及交错键顺序。`compute_m320` 保持原来的唯一键替换语义，不受影响。

mode1 还会先跳过状态为0的缓存字段和 m322/m323，再重建 m306/m307、计算 m320，
最后变换。它不是对完整 mode0 直接 encode_fields。具体还原见
`mtgsig/registration_collector.py` 和 `docs/REGISTRATION_REPORTING_PROBE.md`。

`0x316b5c` 是异常状态检查。返回非零走配置a9回退，不属于正常checksum算法；离线 API 的 `guard_fault=True` 明确拒绝。bundle配置布尔 `0x4d3a1ac` 为1不等于异常，当前真实值1已验证。启动秒值已采集，但健康计算分支的上述结果不依赖它。

## 验证

`tools/verify_registration_m320.py` 运行原始 ARM64/VM指令，替换范围仅内存分配、libc++/ObjC字符串接口和显式运行时配置输入。HMAC、AES、排序与最终混合由原代码执行。`m320_tail_trace.asm` 保留一次逐指令尾部轨迹。

报告：`dump/envelope_recovery/m320_verification.json`。原始context/cache仍为私有文件；报告只含哈希、数量及匹配结果。发布fixture只含合成配置与字段。完整注册仍需以服务端响应另行验收。

`tests/test_registration_checksum.py` 对八组原 VM fixture 做独立回归，覆盖
UTF-8、空值、词典序、长短配置、不同 flag 与 mask；同时检查忽略旧 m320、
不修改输入，以及异常配置和 NUL 字符的拒绝行为。该测试不读取私有缓存，
也不依赖手机、网络或原始镜像。

`tests/fixtures/registration_m320_pairs_vectors.json` 另存五组由原 ARM64 生成的
重复键向量及实际拼接材料。完整真实 device-info mode0 的原 VM/Python/手机结果
同为 `1138034573`；该数字只是本次观测结果，不能作为通用常量。
