# a9 离线加解密

`mtgsig/a9_codec.py` 和 `python -m mtgsig.a9_cli` 实现当前分析的 Keeta SDK 的 a9 编解码，不需要连接手机。支持 AES、标准 Twofish，以及修改 MDS 的 Twofish，均为 128-bit key、CBC、PKCS7，IV 为 16 字节 ASCII `0102030405060708`。

密钥取决于 a9 内压缩数据的 CRC、同一次指纹数据中的原始 `a1`、SDK 的盐、`k3` 和 a1 取字节的偏移参数。当前恢复的派生覆盖 **36 字符 UUID 格式的 a1**。UUID 的大小写和原始字节应保留，不要做标准化。当前配置和历史配置的盐、偏移不同；仅凭单独 a9 不能自动恢复缺失的 a1 和未知配置。

## 命令行

在项目根目录运行，使用已安装 PyCryptodome 的 Python 3。解密输出原始明文字节，不额外插入换行；模式和长度写到 stderr。CLI 不打印 key、provider 或 a1。

完整 mtgsig JSON 可为 `{"a1":"…","a9":"…"}`，也可以包装为 `{"mtgsig":{…}}` 或 `{"mtgsig":"序列化的 JSON"}`：

```sh
python3 -m mtgsig.a9_cli decode -i mtgsig.json -o plaintext.json
```

已经恢复的历史配置有单独的 profile，其中只存 SDK 参数，不包含设备 a1。对应的历史 mtgsig 使用：

```sh
python3 -m mtgsig.a9_cli decode -i old_mtgsig.json --profile mtgsig/a9_legacy_profile.json -o old_plaintext.json
```

该 profile 的盐来自项目现有 `mtgsig/keeta_const.json`，`a1_shift=12`。当前默认配置的 `a1_shift=31`。`--mode auto` 只识别密码分支，不尝试切换这些配置；默认配置验证失败时，应使用样本所属配置。

原始 a9 文本配合本地 profile：

```sh
python3 -m mtgsig.a9_cli decode -i a9.txt --profile profile.json -o plaintext.json
python3 -m mtgsig.a9_cli encode -i plaintext.json --profile profile.json --mode twofish-mod -o generated_a9.txt
```

若输入只有原始 a9，`profile.json` 需提供原始 a1，或另外传 `--a1`。以下 UUID 是虚构示例，应替换为该 a9 对应的真实值：

```json
{"a1":"00112233-4455-6677-8899-aabbccddeeff"}
```

可选字段 `salt_hex` 和 `k3_hex` 分别指定 16 字节盐和至少 10 字节的 k3，均使用十六进制字符串。`a1_shift` 为 0 到 35 的整数。省略时使用该分析版本的当前默认参数。profile 直接指定最终参数，不解释 SDK 的远端动态配置格式。`--a1` 也可指定 UUID，但 profile 可以避免把标识写进命令历史。若命令行、profile、mtgsig 中同时存在 a1，必须一致。

输入、输出默认均为 `-`，代表标准输入和标准输出：

```sh
cat mtgsig.json | python3 -m mtgsig.a9_cli decode > plaintext.json
```

解密默认 `--mode auto`，依次校验 `aes`、`twofish`、`twofish-mod`；也可指定其中一种。自动判定要求 PKCS7、CRC32 和完整 zlib 流全部通过。加密必须明确选用目标分支，默认 `aes`，不支持 `auto`。解压上限默认 4 MiB，通过 `--max-plaintext` 调整。

逐字节复现旧密文时，应保留原始 zlib 流，因为 zlib 版本、压缩级别和 JSON 序列化差异均可能改变压缩字节：

```sh
python3 -m mtgsig.a9_cli decode -i mtgsig.json --compressed-output -o compressed.bin
python3 -m mtgsig.a9_cli encode -i compressed.bin --compressed --profile profile.json --mode aes -o replay.txt
```

复现时的模式要与解密报告的模式一致。重新压缩明文默认使用 zlib level 6，也可用 `--level` 指定。

## Python 接口

```python
from mtgsig.a9_codec import decode, encode, encode_compressed

decoded = decode(a9, original_a1)  # 默认自动判定模式
plaintext = decoded.plaintext
assert encode_compressed(decoded.compressed, original_a1,
                         mode=decoded.mode) == a9
generated = encode(plaintext, original_a1, mode="twofish-mod")
```

## 算法及验证范围

外层格式为 `crc32_hex(zlib_bytes) + base64(CBC(PKCS7(zlib_bytes)))`。派生为：

```text
mask[i] = salt[i] XOR ((a1[i] + a1[(i + a1_shift) % 36]) & 255), i = 0..15
seed = ASCII(crc32_hex) || k3[2:10]
key = seed XOR mask
```

这里的 a1 下标取原始 ASCII 字节，CRC 是八个小写十六进制字符。真机私有 provider 的参数测试中，`a1_shift=(parameter+11)%36`；当前参数 20 对应 31，历史参数 1 对应 12。修改版 Twofish 的 MDS 运算中，除 x 使用的常量从标准 `0xB4` 改为 `0xBC`；q-box、RS 和块加解密轮结构对应标准 Twofish。先前 AES 核 hook 没覆盖相应分支，不能据此排除标准 AES。

当前证据包括：

- 真机 AES 和当前修改版 Twofish builder 的整条 a9 字节复算，以及当前缓存完整 a9 的离线解密与重加密验证。
- 默认配置的 20 个随机 UUID，其 mask 和派生 key 全部与真机一致。
- 两种 Twofish 原生上下文全部 4256 字节 schedule 一致；`tools/a9_native_verify.py` 在 Unicorn 中执行原生 q/MDS、key schedule 和块加解密，共 48 组输入通过。
- `tools/a9_cbc_probe.py` 直接执行真机 SDK 的 AES/Twofish CBC/PKCS7 包装器，包括 VM 路径，三种模式共 15 组通过；使用私有对象、合成 key 和明文，全局分支值保持不变。记录为 `dump/a9_recovery/native_cbc_wrappers_01.json`。
- 两份先前失败的历史完整 mtgsig，使用历史盐、`a1_shift=12` 和标准 Twofish，分别成功解出 1102、1173 字节明文。失败原因是配置差异。
- 用户补充的完整验收样本也通过历史配置与标准 Twofish 解密，得到 1102 字节明文；CRC 和完整 a9 回编码一致。
- 最早的 `dump/v73_capture/a9.txt` 使用历史配置与 AES 成功解密，压缩流逐字节匹配原始 149 字节 `xz.bin`，解压为 708 字节，重新加密的完整 a9 相同。纯状态证据为 `dump/a9_recovery/old_pair_legacy_verification.json`。

常规测试中的向量均为合成输入，不包含实际设备凭据；测试同时覆盖原生块函数和真机 CBC 包装器生成的向量。

```sh
python3 -m unittest discover -s tests -p test_a9_cli.py -v
```

目前本轮核验的当前及历史样本均已找到匹配配置并完成解密。当前交付覆盖已经验证的算法及配置；未来版本或未知动态配置仍需取得相应参数，不能仅从 a9 自动推断。缺少对应 a1 时，CLI 会报缺少输入。历史样本关联过程参见 [A9_OLD_SAMPLE_FINDINGS](A9_OLD_SAMPLE_FINDINGS.md)。
