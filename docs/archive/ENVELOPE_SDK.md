# A envelope 离线加解密

`mtgsig/envelope_codec.py` 已恢复当前 SDK 的 envelope 构造链，并接入 RPC 的 `/envelope/encode`、`/envelope/decode`。四份完整历史业务信封已解密并逐字节重新加密成功，覆盖 `aes`、`twofish`、`twofish-mod` 三种模式；当前同步原生合成样本的 `twofish-mod` 完整信封也可以逐字节重建。

```text
mask             = a9 provider 的 derive_mask(a1, salt, a1_shift)
session_key      = 16 字节随机 payload key
session_material = session_key XOR mask
part1            = raw RSA-1024(session_material, runtime public key)
part2            = CBC(PKCS7(zlib(prepared_plaintext)), session_key)
envelope         = b64(part1).rstrip('=') + '=' + b64(part2)
```

CBC 支持 `aes`、`twofish`、`twofish-mod`，IV 为 ASCII `0102030405060708`。当前非负原生 mode flag `%3` 映射为 `0=twofish-mod、1=twofish、2=aes`。字段采集与 m 系列字段变换在输入阶段完成，不属于 envelope 加密器。

输入阶段不是统一执行字段变换：当前 `/v5/sign` 和 fingerprint info collector 使用 `0x2fc948(mode=0)`，其 JSON 为原始缓存值，默认 `transform="none"`；device-info 使用mode1，才在 m320计算后应用 m-series变换。不要对mode0采样先 decode_fields；可逆往返不能证明编码阶段。四端点与ABI见 `dump/envelope_recovery/REGISTRATION_COLLECTORS.md`，checksum见 [REGISTRATION_CHECKSUM](REGISTRATION_CHECKSUM.md)。

早期“raw RSA 中的 16B 就是 payload key”的结论错在遗漏了 XOR mask。因此直接用 SecKeyEncrypt 输入试 AES/Twofish 均失败，不能据此认定算法是未知白盒。另一把被误称“随机信封 AES key”的抓取 key，与本次真实 payload key 没有关联。

## 使用方式

同一会话应生成并保存一次 key，在多个请求中复用以维持相同 RSA 前缀。下面全部是合成输入：

```python
import secrets
from mtgsig.envelope_codec import encode_sdk, decode_sdk, derive_session_material

a1 = "00000000-1111-2222-3333-444444444444"
session_key = secrets.token_bytes(16)
plaintext = '{"synthetic":true,"sample":"' + 'abcd' * 64 + '"}'
envelope = encode_sdk(plaintext, a1, session_key=session_key,
                      mode="twofish-mod", profile="default")
decoded = decode_sdk(envelope, a1, session_key=session_key)
assert decoded.plaintext.decode() == plaintext

# 已知 RSA 封装前的16B材料也可恢复 payload key。
material = derive_session_material(session_key, a1)
assert decode_sdk(envelope, a1, session_material=material).plaintext == decoded.plaintext
```

API：

| API | 用途 |
|---|---|
| `encode_sdk(plaintext,a1,session_key=...,mode=...,profile=...)` | 默认 zlib level 6 压缩后生成完整信封；省略 key 会每次生成随机 key |
| `encode_compressed_sdk(compressed,a1,...)` | 使用完整 zlib 原始字节，精确重放，不重新压缩 |
| `decode_sdk(envelope,a1,session_key=... 或 session_material=...)` | 先重算核对 RSA part1，再校验 padding、完整 zlib 和输出大小 |
| `derive_session_material(key,a1,...)` | 计算 RSA 封装前材料 |
| `recover_session_key(material,a1,...)` | 从已知封装前材料反求 payload key |

`DecodedEnvelope` 提供 `parts`、`payload`（去填充但未解压）、`plaintext`、`mode`、`profile`、`rsa_verified`。旧 `encode`/`decode`/显式 AES key/IV 接口保持兼容。

profile 必须明确为 `default` 或 `legacy`，也可显式覆盖 `salt`、`a1_shift`。default 使用当前 salt/shift31；legacy 使用项目已验证的历史 a9 provider salt/shift12。当前完整原生 envelope 样本验证的是 default profile；legacy 的 envelope 组合经过离线双向测试，其 mask 来自已验证的历史 provider，不能据此声称抓到了历史完整原生 envelope。

## RPC 请求

沿用 `/envelope/encode` 和 `/envelope/decode`：**body 带 `a1` 使用 SDK 算法；不带 `a1` 保留旧显式 AES key/IV 接口。** SDK 请求不接受旧 `key`、`iv`、`session_key`、`session_material`、`caesar_shift` 字段，避免隐式更改编码含义。

生成信封：

```json
{
  "a1": "00000000-1111-2222-3333-444444444444",
  "plain_json": {"synthetic": true, "sample": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
  "mode": "twofish-mod",
  "profile": "default"
}
```

POST 到 `/envelope/encode`。省略 `session_key_hex` 时，响应包含新生成的 `session_key_hex` 和 `session_key_generated:true`；调用方保存该值，后续加密、解密均可复用。显式传入时必须是32位十六进制字符串，不带 `hex:` 前缀，响应不重复返回它。

解密请求：

```json
{
  "a1": "00000000-1111-2222-3333-444444444444",
  "envelope": "<encode 返回的 envelope>",
  "session_key_hex": "<encode 返回或自己保存的32位hex>",
  "profile": "default"
}
```

POST 到 `/envelope/decode`。如果抓到了 RSA 封装前材料，用 `session_material_hex` 替换 `session_key_hex`，同样严格为32位hex。默认自动识别三种 mode；成功返回 `plain_json`、`mode`、`profile`、`rsa_verified` 和分段长度，不重复打印明文 base64/text，也不回显会话 key。

可选 `compress:false` 与解密的 `decompress:false` 配合使用；未压缩解密需要明确 `mode`。精确重放完整 zlib 可在加密请求中单独提供 `compressed_b64`，此时不能再混入明文字段、`zlib_level` 或 `compress:false`。profile可选 default/legacy，也支持 `salt_hex`、`a1_shift` 明确覆盖。

`GET /health` 新增 `envelope_sdk_ready`、`envelope_modes`、`envelope_profiles`、`envelope_requires_session_key`；最后一个值为 true，说明公开 RSA 信封不能在无会话材料情况下通解。`rpc/smoke.py` 会验收 SDK 三模式、两种已知会话材料解密、自动 key 返回，以及旧显式 AES 路径兼容性；只发送合成样本。

## 解密与压缩边界

只有公开 envelope、a1 和 RSA 公钥时，无法反求 RSA 明文或随机 payload key。`decode_sdk` 必须取得原始会话 key 或 RSA 封装前材料，缺失时明确失败。`session_material` 是16B原始材料，不能把128B RSA密文当作它。新增接口不意味着任意未知会话的 fingerprint 都能离线解密。

`mode="auto"` 默认只尝试三个已验证模式，用 PKCS#7 与完整 zlib 校验选择；不自动尝试未知 profile。对于 `compress=False` 的原始 payload，解密需 `decompress=False` 且明确 cipher mode，避免仅靠碰巧正确的 padding 猜算法。RSA 重算校验只证明材料对应前缀，并不为 CBC payload 提供认证。

原生压缩 wrapper 对压缩膨胀的输入会截断输出（已验证1B、16B合成输入），得到无法完整解压的流。`encode_sdk` 拒绝这种输入，可改用 `compress=False`，或提供业务上正常大小、可压缩的 JSON。`encode_compressed_sdk` 要求一个完整、无尾随数据的 zlib 流；它不重现原生损坏流。明文 C-string 接口同时拒绝空串和嵌入 NUL。

## 验证材料

- `dump/envelope_recovery/builder_native_02.json`：私有原生抓取，六次合成调用；六个 RSA part1全部匹配 masked session material。四个有效输入的完整信封与离线加密精确相等、双向解密匹配；两个短压缩输入按上述边界拒绝。
- `dump/envelope_recovery/builder_a1_correlation.json`：初始化记录中的 a1 派生 mask 与当前对象16B mask精确一致；没有把不同会话 key 混配。
- `dump/envelope_recovery/historical/verification.json`：四份完整历史业务 payload 使用同抓取的 RSA 封装前材料、原始 a1 和 default profile，全部通过 RSA 前缀、PKCS#7、完整 zlib、JSON 及逐字节重新加密校验。其中两份 `twofish-mod`、一份 `twofish`、一份 `aes`；两份解压前 zlib 与同抓取的 CORPSE 事件逐字节相同。原记录未保存 URL，不据此把明文绑定到具体接口。
- `tests/fixtures/a9_native_cbc_vectors.json`：三个 mode 各五个长度的合成 key/plaintext，expected ciphertext来自原生 wrapper；SDK envelope测试直接使用这些15组独立向量。
- `tests/test_envelope_sdk.py`：原生向量、显式 profile、未知会话拒绝、RSA重算、完整zlib、大小限制及短压缩边界。私有原生完整样本存在时额外执行全链对拍，CI没有私有材料时跳过该项。

两份正式 Charles 抓包的 RSA 前缀均不匹配上述历史会话材料，因此未把它们强行解密，也不能把历史信封验证当作新机注册服务端验收。历史证据使用的是 default profile，不增加 legacy 完整原生 envelope 的验证范围。

原始 key、a1、对象值保留在私有抓取中，不复制到公开测试 fixtures；历史明文单独保存为权限 0600 的文件，报告仅记录哈希、长度和字段类型。运行：

```sh
python3 -m unittest tests.test_envelope_codec tests.test_envelope_sdk -v
python3 -m unittest tests.test_envelope_rpc tests.test_rpc_smoke -v
python3 tools/verify_historical_envelopes.py
```
