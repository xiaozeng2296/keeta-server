# m324 与 a9 会话字段

> 历史研究资料，来源 `codex/keeta-project@6197c528`；保留当时的观测与未完成项，不代表新项目当前状态。当前规则见 [字段状态](../MTGSIG_FIELDS_STATUS.md)，复跑入口及已修正结论见 [离线研究指南](../research/OFFLINE_RESEARCH.md)。文中的旧 `dump/`、抓包及设备路径仅作证据索引，原材料未随仓库发布。

当前镜像中的 m324 是 **32 字符大写 UUID + 初始化线程标志 + 固定字符 `1`**。它不是设备下发密文，也不是 17 字节随机密钥。

```python
from mtgsig.session_identity import m324_from_uuid

# 显式输入；同一次 SDK 会话只生成一次，并保存供后续请求复用。
session_m324 = m324_from_uuid(
    "12345678-1234-4234-8234-123456789abc", main_thread=False)
# 12345678123442348234123456789ABC01
```

`main_thread` 指首次执行原生初始化块的线程。主线程为 `1`，其他线程为 `0`；不是每次签名所在线程。该 UUID 来自独立的 `NSUUID.UUID`，没有从 IDFV、OneID、SAK 本地 UUID、a1 或时间派生。API 不自动生成随机数，不维护隐式全局缓存，生命周期由调用方管理。

原实现通过 `dispatch_once` 在当前已加载镜像/进程内缓存一次，未发现该构造路径读写 Keychain 或磁盘。重启进程会重新初始化；不得据此把值做成跨全部设备共享常量。

## 原生数据流

- collector `0x34eaa4` 的 `0x350e8c[324-122]` 指向 `0x34fb28`，调用 `0x33f5b0`。
- `0x33f5b0` 使用 once token `0x4d3cfe8`，block `0x4061af0` 的 invoke 为 `0x33f5f0`。结果缓存于 `0x4d3cfe0`。
- `0x33f6ac..0x33f6f4` 调用 `+[NSUUID UUID]`、`UUIDString`、`UTF8String`。类引用 `0x4b37c40` 绑定 `_OBJC_CLASS_$_NSUUID`。
- `0x33f874..0x33f880` 经 `0x38fda8` 将 UUID 中的 `-` 替换为空。
- `0x33f8a4..0x33f8cc` 调 `+[NSThread isMainThread]`，选字符 `1` 或 `0`。
- `0x33f970..0x33f98c` 先拼线程字符，再调用 libc++ `string::append(char const*)` 追加固定 `1`；随后转 NSString 并存入缓存。
- 三个短常量从 `0x331d7a8` 使用 seed `0x8c/0x90/0x91` 解出 `-/1/0`。

## 与 SIUA 的同源关系

`0x38de54` 将 `0x333e5a0` 的 167 字节配置用 seed `0xc7` 解混淆。配置中 `2` 的字段序列为：

```text
1|148|132|294|142|143|154|144|131|150|153|157|253|254|255|315|324|127|166
```

因此 `SIUA['2'][16]` 对应 collector **324**。`0x38e050` 将该序列解析为 `object+0xb0` 的 ID 数组；`0x38e6f4` 在 `0x38eafc..0x38eb10` 依次取 ID，经 `0x2e85e4 → 0x2e9428` 读取共享 cache，追加到输出 `2` 数组。

A envelope serializer `0x2fc948` 在 `0x2fca5c..0x2fca68` 通过同一 cache getter 读取对应字段。`0x2e9428` 的语义就是 `cache + signed(field_id) * 32`。这确认了两处共用同一 collector 值，除静态调用链外，当前 context02 的三路 m324 与解密 a9 的第 16 项也全部一致。

缓存尚未采集时 SIUA 可能输出 `-`；应保留观察到的采集状态，不能把有占位符的旧 profile 直接解释为当前完整 profile。上述索引映射对应当前配置，其他版本/动态配置需要另行验证。

## 绑定顺序及验收

新会话生成一次 `session_m324` 后，将同一值写入各 A payload 的 `m324` 及 `base_siua['2'][16]`。随后重算每路 m320、重编码 a9、构造 A envelope，最后计算请求 mtgsig。m324 没有作为加密 key 输入；更换字段仍必须刷新依赖其明文字节的校验/密文。

目前只交付生成 API 和绑定方案，未自动改主 flow，也未修改已成功注册的 `session_02` 历史身份。

`tools/verify_m324.py` 执行原 ARM64 `0x33f5f0` 构造块，仅提供外部 ObjC、libc++ 和内存服务。三组合成 UUID × 两种初始化线程，**6/6 与 Python 完全匹配**。发布 fixture `tests/fixtures/m324_native_vectors.json` 仅含合成输入输出；源头检查及二进制 hash 在 `dump/m324_recovery/verification.json`。

```sh
PYTHONPATH=/tmp/keeta_a9_deps python3 tools/verify_m324.py \
  --report dump/m324_recovery/verification_next.json
python3 -m unittest tests.test_session_identity -v
```

验证未操作手机或请求网络。工具依赖本地 Mach-O/Unicorn，仅用于分析，不随 RPC 发布；纯 Python helper、合成 fixture 和单元测试随包。
