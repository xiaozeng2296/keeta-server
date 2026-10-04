# Incognia unique request token：真实生成链与离线对拍

> 历史研究资料，来源 `codex/keeta-project@6197c528`；保留当时的观测与未完成项，不代表新项目当前状态。当前规则见 [字段状态](../MTGSIG_FIELDS_STATUS.md)，复跑入口及已修正结论见 [离线研究指南](../research/OFFLINE_RESEARCH.md)。文中的旧 `dump/`、抓包及设备路径仅作证据索引，原材料未随仓库发布。

本次已还原 `incog-token` 的七字段明文模型及完整加密封装，新增独立离线编码/解码模块。它是登录请求的一个 header，和 `mtgsig.a9`、`fingerPrintData` 的 A-envelope 是三条不同链路。

证据基于当前 `dump/Keeta.dec` 的 ObjC/ARM64 静态调用链，以及同版本运行的 `boundary_current_01.json`、`boundary_current_02.json`。四枚原生 token 的压缩、AES、HMAC、拼接和返回值均已对拍。报告不包含真实 token、密钥、账号或 installationId。

## 实际封装

```text
J = UTF8(JSON)
Z = raw-DEFLATE(J)
K = SecRandomCopyBytes(32)
IV = SecRandomCopyBytes(16)
C = AES-256-CBC(K, IV, PKCS7(Z))
R = RSA-2048-OAEP-SHA256(publicKey, K)
M = HMAC-SHA256(SDK固定配置HmacKey, IV || C)
token = Base64URL(0x00 || R || IV || C || M)，去掉末尾 =
```

四枚观测样本均为 556 字符，解码 417 字节：`1 + 256 + 16 + 112 + 32`。417 不是固定协议长度，JSON 压缩长度变化后，AES 密文长度可以变化。

已证实：

- 加密 `CCCrypt` 的参数为 `op=0, algorithm=0, options=1`，key 为 32 字节；就是标准 AES-CBC/PKCS7。
- 传给 RSA 的 32 字节，与 AES key、对应随机调用结果完全一致。
- `SecKeyCreateEncryptedData` 运行参数为 `algid:encrypt:RSA:OAEP:SHA256`。
- HMAC 使用 `CCHmacInit/Update/Final`，算法值 2，即 SHA256；只 hook 单次 `CCHmac` 会漏掉。
- HMAC 覆盖 `IV || C`，不覆盖 RSA 段或格式头；离线解码器会额外检查格式头和固定分段长度。
- SDK 字符串常量经 AES 解混淆后的公钥，与第二轮导出的真正运行公钥相同。固定 HMAC 配置同样来自这条常量解混淆链。
- 当前四个样本 Python zlib level 6 的 raw-DEFLATE 字节与 iOS 输出完全相同。其他输入上若压缩器输出不同，需要区别“解压等价”和“压缩字节完全一致”。

解出 token 仍需要对应 AES 会话 key；RSA 公钥只能生成新封装，不能从任意抓包逆推出随机 key。此次成功解码依据运行边界中观测到的会话 key，不能据此声称任意历史 `incog-token` 都能只靠抓包解开。

## 七个明文字段

| 字段 | 已证实来源 | 生命周期 |
|---|---|---|
| `1` | `applicationId` | SDK 初始化参数；不是 `mtgsig.a1` |
| `33` | `installationId.replace("ILM-ID-", "").lower()` | 安装身份；UUID 连字符保留 |
| `50` | 字面整数 `62300` / `0xf35c` | 当前 SDK 常量；未给它强行命名为版本或标记 |
| `73` | 基础对象构建计数器的自增前值 | 从持久存储读取，存入 `+1`，旧值写模型 |
| `74` | 基础对象构建的 `floor(NSDate.seconds * 1000)` | 基础对象缓存期间保持 |
| `59` | 请求计数器的自增前值 | 每次 unique token 生成读取并存入 `+1` |
| `60` | 该次生成的 `floor(NSDate.seconds * 1000)` | 每次生成更新 |

连续调用中仅 `59`、`60` 改变，`59` 增加 1。四枚原生 JSON 均可由 `build_payload()` 逐字节重建；字典顺序采用当前观测顺序，传入原始 JSON bytes 时 `encode()` 保持该输入序列化。

安装身份来源函数先按存储选择开关读取两套 wrapper 之一；缺失才调用 `NSUUID.UUID.UUIDString` 创建身份并保存。这证明这一直接输入是持久安装标识，不支持旧脚本注释中“它必然是 Secure Enclave 硬件锚”的推断。SDK 的其他遥测、后台注册和服务端关联尚未在此文档中还原，不能把换一个 UUID 等同于完成新安装注册。

## App 层的真实调用与缓存

```text
SLAppLanucher didFinishLaunching
  -> SOAAccountUIConfig.getIncogTokenBlock
     -> SLIncogniaManager.isIncogniaEnabled
     -> SLIncogniaTokenManager.getCachedToken
        -> 返回当前缓存的 copy
        -> 未 refreshing 时异步发起刷新
           -> ICGIncognia.generateUniqueRequestTokenSync（后台队列）
           -> 新值非空才替换 cachedToken，最后清 refreshing
```

`isIncogniaEnabled = switchEnable && regionEnabled && isInitFinnish`。`SAKBaseModel.getCommonHeaderFields:` 还受 `disableAddIncogniaOnRequest` 控制，只有 token 非空才附加 header。

缓存含义：当前请求拿到的通常是之前生成的 token，刷新用于后续请求。相邻请求出现重复 token 是这条实现的自然结果，不能简单认定每个 HTTP 请求必须有不同 token。失败时保留旧缓存。

`generateUniqueRequestTokenSync` / `generateRequestTokenSync` 都是**不带冒号**的无参 selector，带超时的是 `generateUniqueRequestTokenSyncWithTimeout:`。内部 unique 实现拒绝主线程同步调用，主线程返回 nil 不表示算法缺失；本次生成调用在 Frida 工作线程执行。

## 可重放的验证

```bash
python3 -m unittest tests.test_incognia_token -v
python3 tools/verify_incognia_boundary.py \
  dump/incognia_recovery/boundary_current_01.json \
  dump/incognia_recovery/boundary_current_02.json
```

- `mtgsig/incognia_token.py`：`build_payload`、`encode`、`split`、`decode_with_session_key`，无联网、无手机依赖。
- `tools/verify_incognia_boundary.py`：按调用栈归属关联真实 JSON、随机数、AES、RSA 和最终 Base64；stdout 仅输出长度、文件摘要和布尔验证项。
- `tests/test_incognia_token.py`：五项测试通过，包括合成 RSA 私钥解开新 OAEP 段后的整链往返、相同明文产生不同随机封装、篡改拒绝及解压限制。
- 私有配置 `dump/incognia_recovery/algorithm_profile.json` 权限 0600，含 SDK public key、固定 HMAC 配置、applicationId 和常量 62300；不含原 token、installationId 或账号。可通过验证脚本 `--profile-out` 导出到一个不存在的新文件。

四枚原生 token 的精确封装对拍是在验证脚本内复用**该条观测的 RSA 输出段**，其余压缩、AES、MAC 均独立重算。这是明确的验证边界：RSA-OAEP 本身有随机填充，未捕获原生 OAEP seed，不能声称 Python 新随机加密会和原 RSA 段字节一致。生产 `encode()` 从公钥新算 RSA 封装，不接受旧 token 或旧 RSA 段输入；合成 RSA 私钥往返验证了新封装可解。

## 关键静态证据位置

地址均为当前 Mach-O 的 RVA，base 为 `0x100000000`。

| RVA | 作用 |
|---|---|
| `0x22777b4` / token block `0x227848c` | App 注册及 token block |
| `0x2b46708` | `SAKBaseModel getCommonHeaderFields:` |
| `0x2e10944` | enabled 三条件 |
| `0x2e10f28` / `0x2e10fb0` | 读缓存 / 异步刷新 |
| `0x2e11200` / `0x2e11284` | 后台调用 unique sync / 更新缓存 |
| `0x1adbe1c` / `0x1adbe28` | unique sync / timeout public API |
| `0x1b36338` | 主线程检查、准备及等待 |
| `0x1b6d240` / `0x1b6d3f4` | unique 生成 / 基础对象构建 |
| `0x1b14250` | 安装身份读取、缺失生成和保存 |
| `0x1b39b84` / `0x1b30d48` | 五字段基础模型 / 追加 59、60 并 JSON 序列化 |
| `0x1b55c84` | 全封装编排 |
| `0x1b64e18` | NSData compression（raw-DEFLATE） |
| `0x1b55460` / `0x1b552d4` | 生成 IV / AES 后前置 IV |
| `0x1b564f8` / `0x1b56108` | HMAC 附加 / Init-Update-Final |
| `0x1b66c60` | RSA OAEP 加密 |
| `0x1b2c2e8` | URL-safe Base64 替换及去 padding |
| `0x1b08804` / `0x1b08818` / `0x1b0882c` | HMAC 配置、公钥、SDK 常量解混淆 |

## 旧材料应纠正的归因

`tools/keeta_incognia_recon.py` 写成了带冒号的无参 API，未命中不能排除 SDK。`keeta_incognia_v3_decode.py` 的旧工件只有广泛 JSON 事件，没有能关联到 Incognia 封装的密码事件。`keeta_step3_incognia.py` 同时改变 token、installationId、网络和设备状态，不能据其输出定位 DFP 合并原因。App Attest 工具中的注释也不是硬件关联结论。

当前下一验证是新机前后字段 33/73/74/59 的变化、安装注册生命周期与业务登录响应；还原这个 header 不代表验证码发送或登录已得到服务器接受，也不证明 DFP 的归并由 Incognia 单独决定。

## 请求构造中的显式状态接口

新增 `mtgsig/incognia_state.py`，已接入 `keeta_offline_flow.build_request()`。调用点位于最终 URL、body、区域 header 确定之后，`mtgsig` 签名之前。

配置分为算法和当前安装状态，二者均由调用者明确提供：

```python
profile['incognia'] = {
    'enabled': True,
    'enabled_regions': ['BR'],
    'algorithm': algorithm_profile,  # 从私有 algorithm_profile.json 加载
}
profile['incognia_state'] = {
    'installation_id': current_installation_id,
    'initialization_counter': observed_initialization_counter,
    'initialized_at_ms': observed_initialization_time_ms,
    'request_counter': next_request_counter,
}
```

`algorithm_profile` 需要 `format=0`、`public_key_pem`、`hmac_key_hex`、`application_id`、`sdk_code`。没有算法参数或安装资料时不自动填造 identity。

- 最终 region header 优先于 profile 中的区域值。HK 不在示例 enabled_regions 中，因此移除旧 `incog-token`，不生成、不耗计数；不从域名猜区域。
- 模板提取时移除各种大小写的捕获 token，避免无来源继承。存在 `incognia` 配置时由新模块完全管理该 header，覆盖 profile/header override：disabled 或未启用区域删除，启用区域新生成。**没有新配置时**保留既有 `profile['incog-token']` / `header_overrides` 显式传入当前手机 token 的兼容入口，不把它静默删掉。
- `request_counter` 是**下一次待用值**。生成前将 `+1` 写入 `signer.dev['incognia_state']`；加密、签名或发送失败后不回退。继续构造时以保存值和显式输入值的较大者为准。
- 安装身份或初始化计数/时间与 signer 当前状态不一致会报错，不把两个安装的计数拼在一起。确实新建安装应使用独立 signer/state。
- 不把生成 token 保存进 profile/state。snapshot 保存动态 state，续接时可以不再提供 seed，但仍需要保留显式 `profile['incognia']` 开关和算法配置。
- 无 signer 的纯模板构造只去掉旧 header，不生成 token。调用方原有 dry-run signer clone 继续只修改 clone，不修改输入 profile 或实际 signer。
- OneID/newreg 两个既有 `UNSIGNED_PATHS` 不经过该签名 header 生成，不要求区域输入、不耗 Incognia 计数。
- 模块在进程内加锁完成计数预留；落盘沿用调用方现有私有 snapshot 路径。它不提供跨进程数据库锁，也不声称未落盘的状态能跨崩溃保存。

`tests/test_incognia_state.py` 的十项测试验证逐次解密得到的计数、HK 不启用、捕获 token 不继承、显式旧入口兼容、生成/签名/传输失败后不回退、JSON snapshot 续接、clone 隔离及 unsigned bootstrap 不耗计数。
