# a9 provider 的配置边界

> 历史研究资料，来源 `codex/keeta-project@6197c528`；保留当时的观测与未完成项，不代表新项目当前状态。当前规则见 [字段状态](../MTGSIG_FIELDS_STATUS.md)，复跑入口及已修正结论见 [离线研究指南](../research/OFFLINE_RESEARCH.md)。文中的旧 `dump/`、抓包及设备路径仅作证据索引，原材料未随仓库发布。

本页记录当前分析版本的 provider 布局及后续研究入口，不包含设备 provider、实际 key 或安装标识。离线 codec 接受最终的 `salt`、`a1_shift` 和 `k3`；动态配置由新增 `mtgsig/provider_config.py` 解码，再传入最终参数。SDK 对象内的 `parameter` 按下述关系换算为 `a1_shift`。

> 2026-10-01 真机补充：`parameter`（对象 +88）就是当前原生 mtgsig.a3 的直接来源。App 3.12.500/build 18565 启动时，构造器先写 20，配置处理函数 `0x30c490` 成功后改为 25，最终签名输出 25。读取此时真实 provider 验证：原生 salt + shift=0 可重现 mask，`(25+11)%36=0`；项目 legacy 的等效 salt + shift=12 也重现同一 mask。旧隔离实验的 parameter=1 不能当作 native legacy 的实际值。下面的隔离实验保留为历史记录，配置载荷现已解出 a3/salt JSON 并经独立原生对象验证。新证据见 [原生字段观察](../research/NATIVE_FIELDS_20261001.md)。

## 已确认的 provider 布局

`K+0x30c408` 的原生构造函数分配 96 字节对象，清零前 72 字节，从 `K+0x333fb30` 复制 16 字节默认盐至偏移 72，并将偏移 88 的 32 位参数设为 20。这几步是直接 ARM64 指令，不依赖对 VM 字节码的推测。

| 偏移 | 长度 | 当前已知用途 |
|---|---:|---|
| `0` | 16 | 初始化后的明文 provider mask |
| `16` | 16 | envelope payload 的随机会话 key；a9 可结合下一项还原 mask |
| `32` | 16 | RSA 封装的会话材料 = mask XOR payload key |
| `48` | 24 | RSA 封装后 base64 前缀的 libc++ std::string |
| `72` | 16 | 用于 a1 派生的 salt |
| `88` | 4 | 派生旋转参数 parameter |
| `92` | 4 | 未在本轮静态分析中确定 |

`K+0x30c52c` 直接执行循环：生成随机字节，写至 `object[16+i]`，再将其与 `object[i]` 异或后写至 `object[32+i]`。这两个区域在 a9 派生中用于还原稳定 mask；在 envelope 中，前者直接作为随机 payload key，后者被 raw RSA 封装。当前 native envelope 样本已验证此关系，详见 `docs/ENVELOPE_SDK.md`。

## 最终派生参数的含义

对 SDK 使用的 36 字节 ASCII UUID，私有对象单变量实验得到：

```text
shift = (parameter + 11) % 36
mask[i] = salt[i] XOR ((a1[i] + a1[(i + shift) % 36]) & 255), i = 0..15
seed = crc32_hex(zlib_data).ASCII + k3[2:10]
key[i] = seed[i] XOR mask[i]
```

参数实验的原始材料是 `dump/a9_recovery/provider_parameter_cases.json`、`provider_parameter_results.json`；默认参数 20 对应 shift 31。参数 1 对应 shift 12，与项目已有历史盐共同解开了旧抓取样本，包括原始 149 字节 xz 配对。具体独立样本验证见 [A9_OLD_SAMPLE_FINDINGS](A9_OLD_SAMPLE_FINDINGS.md)。

这里的 `parameter` 是对象偏移 88 的数值；2026-10-01 真机实验已证明配置 JSON 字段名为 `a3`，16 字节盐来自 `salt` 的十六进制解码。已有命名 profile 继续有效，新的显式配置可经 `ProviderConfig` 解码并对拍。36 字节以外的输入在原生流程中表现为截断/补零至固定长度；正式 codec 限制为原始 UUID，避免将这个边界行为当作支持的公共输入。

## 动态配置的静态入口

以下入口均将参数保存到调用栈，再调用通用 VM `K+0x397d80`：

| 原生入口 RVA | VM 字节码 RVA | 字节码长度 | 已观察用途 |
|---|---|---:|---|
| `0x30c454` | `0x3310c54` | `0x30c` | provider、a1、动态配置的初始化入口 |
| `0x30c490` | `0x3310f60` | `0x13b0` | 双参数配置处理入口；返回结果被 `and w0,w0,#1` 归一化 |
| `0x30c5d8` | `0x3312310` | `0x818` | 生成并保存 RSA 会话前缀；材料来自对象 +32 |
| `0x30c618` | `0x3312b28` | `0x2e4` | 根据 seed 产生派生结果 |
| `0x30c670` | `0x3312e0c` | `0x240` | 返回对象 +16 的会话 key 指针；四组合成对象原指令验证通过 |

它们共用 `K+0x405fbf0` 的指针引用表。该表中能直接看到 provider 方法、字符串存储地址、字符串解混淆函数 `0x2dd248` 以及其他内部函数；它不是“固定 AES key 表”。仅凭这张表和 VM 包装函数，还不能可靠恢复下发配置字段名、解析规则或签名/编码要求。

项目中保存的动态配置键名为 `sakguard_dynamic_enc_salt_config_key`。该键名说明了配置读取边界，但不能代替实际 value 格式的证据。

## 可继续复用的离线实验

`tools/a9_provider_emulate.py` 是隔离的探索工具：只读取 Mach-O，在 Unicorn 内运行原始 VM 指令，输入固定合成 UUID 和指定的合成配置，不连接手机、不写 App、不修改二进制。它复用了 `tools/a9_native_verify.py` 的镜像映射，并提供本地内存分配、常见 libc 字符串函数、单线程 mutex/once 语义和确定性时间/随机服务。

截至本次记录，运行 `--parser-only` 已完成 VM 字节码解码、内部对象分配和类型构造，但在 `___dynamic_cast` 导入处主动停止：调用点 `K+0x3a41dc`，对象类型为 `jg_vmp::IntegerType`，父类为 `jg_vmp::Type`。工具没有伪造这个导入的成功返回，因此**该旧离线 VM 探索没有执行完成**；此后通过真机私有对象已完成配置解析对拍。它不是现有 codec 的依赖，也不应作为动态配置已还原的证明。

当前交付的双向 a9 恢复由真实历史样本、当前样本及独立 ARM64 密码核心对拍支持，不依赖这个尚未完成的配置解析实验。若将来出现新远端配置，先用 `protocol_watch.py native/audit` 解码与对拍；不匹配时再从此解析边界继续，并同时保存原始配置值与对象偏移 72/88 的变化，不能从一次未知配置失败推断密码算法改变。
