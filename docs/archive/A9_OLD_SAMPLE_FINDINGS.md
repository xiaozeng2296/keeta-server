# a9 旧样本来源核查（2026-09-28）

> 历史研究资料，来源 `codex/keeta-project@6197c528`；保留当时的观测与未完成项，不代表新项目当前状态。当前规则见 [字段状态](../MTGSIG_FIELDS_STATUS.md)，复跑入口及已修正结论见 [离线研究指南](../research/OFFLINE_RESEARCH.md)。文中的旧 `dump/`、抓包及设备路径仅作证据索引，原材料未随仓库发布。

本次只读取项目抓取材料及项目明确引用的 `/tmp/keeta_K.json`，未访问设备、网络或认证存储。先用有完整 a1/a9 关联的历史记录校准配置，再验证有限且保留来源的既有 UUID 候选，没有枚举任意密钥。

## 最终结果：原始 149 字节配对也已精确解开

`dump/v73_capture/a9.txt`（CRC `c55315ed`）实际使用 **AES**，配合 `mtgsig/keeta_const.json:salt`、parameter 1（shift 12），以及下述两条完整历史记录共同的 a1：

- `dump/a2tables/keeta_K_sample.json:mtgsig.a1`
- `/tmp/keeta_K.json:mtgsig.a1`

解密通过严格 PKCS7、CRC32 和完整 zlib 校验。解出的 149 字节压缩数据与原 `dump/v73_capture/xz.bin` **逐字节完全一致**，明文为 708 字节，重新加密后的完整 224 字符 a9 与原文件完全一致。

该 a1 同时存在于 `win_143073800_33.bin`。对已有来源索引中的 18 个 UUID，以已经从完整历史记录验证过的同一盐和旋转配置、三种真实算法进行有限校准，只有该 a1 + AES 命中。此结果现在构成密码学上的关联证据；此前不能仅凭窗口位置预先宣称其为正确 a1。

结果见 `dump/a9_recovery/old_pair_legacy_verification.json` 和 `old_pair_legacy_candidates_results.json`，均未保存原始 key 或 UUID。

## 已独立解开的历史样本

`dump/collect_plain/login_fp_plain_reinstall.json` 内同一 `mtgsig` 对象包含 `a1` 和 `a9`。使用 `mtgsig.a9_codec.decode` 的默认盐和配置：

- 自动识别为 `twofish-mod`。
- CRC 前缀为 `cf044500`，压缩数据为 561 字节，解压明文为 1224 字节。
- 明文是含 `0,1,2,3` 字段的 SIUA JSON。
- 保留原压缩数据重新加密后，与历史 `a9` 全字节一致。
- 明文 SHA-256：`dfc987aa5b631a2dcb26c60fe79e9a970aeb4614338411d425b28e75f725fe72`。

这是一条历史抓取的独立成功向量，不是新实现自己生成再自己解密的自洽测试。可复现：

```python
import json
from pathlib import Path
from mtgsig.a9_codec import decode, encode_compressed

m = json.loads(Path("dump/collect_plain/login_fp_plain_reinstall.json").read_text())["mtgsig"]
d = decode(m["a9"], m["a1"])
assert d.mode == "twofish-mod"
assert len(d.plaintext) == 1224
assert encode_compressed(d.compressed, m["a1"], mode=d.mode) == m["a9"]
```

## 149 字节旧配对的实际来源

`dump/v73_capture/xz.bin` 和 `a9.txt` 的最后修改时间均为本机时间 `2026-09-27 23:13:54`。压缩数据 SHA-256：

`35c24ee270b2537c603e8ddfdebfca5074cb85b0e81bab0e527f8f579c4d48f4`

已确认：149 字节 zlib 解压为 708 字节 JSON；其 CRC32 为 `c55315ed`，与 a9 前缀一致；密文长度为 160 字节。

但采集工具 `tools/keeta_stalker_v73.py` 有以下来源限制：

1. 读取 `NSMutableURLRequest` 的完整 `mtgsig` 头后，只用正则提取并发送 `a9`，未保存同头的 `a1`、完整头、时间或配置。
2. Python 将本轮所有压缩输出和所有 `a9` 按 CRC 匹配，并选择首个匹配。若同一轮出现相同压缩数据但不同配置加密的 a9，字典会保留最后一条 a9。
3. 未匹配时仍可覆盖 `a9.txt`，而不覆盖 `xz.bin`。目前两个文件的同次写入时间及 CRC 一致支持它们确实由匹配分支保存，但不补足原始 a1/config。
4. 目录没有按运行隔离，也未清理旧窗口。现存 132 个 `win_*.bin` 实际混合四轮抓取：20:58:27（32 个）、21:08:41（30 个）、21:20:12（33 个）、23:13:54（37 个）。任意旧窗口的 UUID 不等于这条 a9 的原始 a1。

项目内包括隐藏文件的精确密文搜索，只找到 `dump/v73_capture/a9.txt`。窗口内未找到这条完整 a9、CRC 字符串或完整 xz。采集程序在加密开始前启动追踪，窗口没有后续完整头并不意外。

## 可确认与不可确认的配置

- 同轮 `win_141fc8400_58.bin` 和 `win_141fc8800_101.bin` 含 SDK JSON 配置；其中 `k3` 与当前 codec 的 `DEFAULT_K3` 全字节一致。
- 上述 JSON 中的 `a1` 是整数配置项 `1`，不是请求头中的安装 UUID。
- `old_uuid_candidates.json` 的 18 个 UUID 来自跨四轮窗口，均无与确切 a9 同记录的绑定。此前全未解开不证明算法错误，也不能证明正确 a1 已试过。
- `old_provider_candidates.json` 的四段候选均含默认盐且内容一致，但不符合已确认的 provider 结构：掩码关系不满足，偏移 88 的值也不是运行时对象的 20。它们更像常量邻域，不能作为 provider 对象证据。
- 旧 xz 的 SIUA `1` 数组 16 项全为 `"-"`，`2` 数组除第 3 项的嵌套 JSON 外其余 22 项也全为 `"-"`，`3` 为 `"{}"`。这符合早期占位采集形态；“provider 初始化前生成并缓存”仅是待验证假设。

后续按已确认的 provider constructor 语义验证了一个有来源的初始态：`0x30c408` 将前 72 字节清零，再写入默认盐和参数 20，因此此时 provider mask 为零，候选 key 为 `crcASCII + DEFAULT_K3[2:10]`。对 `c55315ed` 旧配对及下列全部历史记录分别验证三个密码分支，均未通过严格 PKCS7、CRC32 和 zlib 检查。该零掩码假设未命中，不应为此添加自动回退。后续成功结果使用的是历史配置下正常的 a1 派生。

## 历史配置差异已验证

设备上的私有 provider 测试后来证明：旋转不是始终 31，而是 `shift = (parameter + 11) % 36`；默认 parameter 为 20。依据这条原生语义，对有真实同记录 a1 的历史样本进行有限的 36 种旋转配置判定：

- 默认盐：只有上述 reinstall 样本在 shift 31 / parameter 20 / `twofish-mod` 下通过。
- `mtgsig/keeta_const.json:salt`：`dump/a2tables/keeta_K_sample.json`（CRC `e626c00d`）在 shift 12 / parameter 1 / `twofish` 下通过，xz 503 字节，明文 1102 字节。
- 同一历史盐、shift 和模式：`/tmp/keeta_K.json`（CRC `bd27110a`）通过，xz 552 字节，明文 1173 字节。
- `workspace/acct_546/sample_K.json`、`workspace/acct_y1/sample_K.json`、`workspace/acct_y2/sample_K.json` 均为同一个 `bd27110a` 样本及 a1 的副本。

两种新命中都通过严格 PKCS7、CRC32、完整 zlib 流检查，并重新加密全字节一致。这些文件的 a1 与 reinstall 样本完全相同，失败原因是配置不同。历史盐原已保存在项目常量文件，提取依据见 `tools/keeta_dump_salt.py`；本次没有猜测新盐或枚举密钥。

结果元数据保存在 `dump/a9_recovery/historical_rotation_results.json` 和 `historical_legacy_salt_results.json`，不包含原始 key、a1 或解密明文。部署使用时必须绑定对应的 SDK salt、parameter 和 k3，不能把默认配置当作所有历史版本的统一配置。

旧配对与三种独立完整历史请求现均已解开。剩余的来源限制仍值得保留：原采集脚本没有保存完整头和动态配置，不能只凭目录共存推断其他样本的身份与配置；应以完整关联捕获或严格加解密校验建立关系。
