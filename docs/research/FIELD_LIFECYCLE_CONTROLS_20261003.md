# 字段来源、a7 刷新接入与 render 对照（2026-10-03）

本文记录本日较早的审计状态。当时店铺采集没有主动获取新 a7。代码已有 `/fingerprint/v1/info/report` 成功响应解析、签名器回填和独立注册流程接入，但数据库 worker 与本地批次执行器没有调用该接口，也没有 a7 过期刷新调度。不能把库中存在处理方法表述为采集流程已经自动刷新。

本轮在 #136 上完成 24 次有界请求：1 次主菜单、23 次 render；17 次 HTTP200 且有效数据，7 次 HTTP403。新材料混入旧 b7、a10 或 provider 参数可触发拒绝，恢复基线即成功；完整后台旧材料本身也成功。a7 两种变体均成功。因此本轮发现了部分材料组合的拒绝条件，尚未解释历史批次及其他账号的 403。

后续已完成 #44 自身材料生成上报、真实有效期分析及执行器到期续接；最新状态见 [a7 实际刷新](A7_REFRESH_20261003.md)。下方接入表保留为本轮修复前证据，不代表最新代码。

## a7：接口、响应和实际接入（修复前）

实际链条为：

1. 使用当前设备/会话身份签名 `POST /fingerprint/v1/info/report`，请求体包含独立的 `fingerPrintData` 上报材料。
2. 请求签名内的 a7 是上报前正在使用的值；不能从这条请求直接读出尚未返回的新值。
3. 接收成功响应中的 `data.result`，更新当前设备的 XID。
4. 同步签名器并持久化；后续请求带新 a7，按照最终 method、URL、body 和完整 payload 重算 a2。

已观察 host 为 `pikachu-eu.mykeeta.com`，旧区域抓包也有 `pikachu.mykeeta.com`。该接口与 `/v5/device-info` 不是同一路径。上报体不是菜单请求体；不能只换 URL，或跨设备借用 `fingerPrintData` / 响应结果。

| 层次 | 代码位置 | 当前行为 |
| --- | --- | --- |
| 响应校验 | `mtgsig/registration_state.py:36` | 对应路径、实际 HTTP 2xx、整数业务 code=0、非空合法 data.result 才产生更新 |
| 身份回填 | `mtgsig/registration_state.py:81` | 更新 a7、a7_server_xid、xid；已有本地候选保留 |
| 活动签名器 | `farm/fullsign.py:369` | 同步 dev 与实际使用的 self.a7；只改外部字典不足以替代此步骤 |
| 保存和重载 | `farm/fullsign.py:431` | 显式 persist_counter 保存当前 dev，包括已回填的服务端值；重载可继续使用 |
| 独立注册流程 | `keeta_offline_flow.py:777` | 发出注册链请求后解析并调用上述回填方法，继续推进有效身份 |
| 数据库店铺 worker | `farm/mysql_worker.py:436` | 仅构造、签名、发送业务任务，没有主动 fingerprint 上报/回填支路 |
| 本地店铺执行器 | `.private/local_batch.py:357` | 同样没有主动上报或刷新支路，继续复用保存的 a7 |
| 到期管理 | 当前未接入 | 解析器没有保存响应 data.serverTimestamp、data.interval；采集器没有对应调度 |

离线处理器验证结果见 `exports/field-lifecycle-20261003/a7-handler-validation.json`：历史响应作为测试 fixture，复制的 signer 更新后，下一次签名使用 response.result；保存重载后仍相等；输入快照未变。serverTimestamp 和 interval 均未保存。该验证没有发网络请求，也没有把历史响应写入生产账号，不代表当前账号已完成线上刷新。

最新用户提供的 fingerprint 请求 userid 与本轮 #136 不同。本轮没有发送该上报 curl，也没有把它的材料混到 #136。只有请求、没有对应响应时，不能声称已经取得该次返回的新 a7。

### 服务端值与本地候选

- 原生 `SAKGuardDeviceFingerprint +getFingerprintXID`（RVA `0x3473c0`）读取 `static_dfpXID`；为空时调用本地生成器。
- `-generateLocalXID`（`0x347ac0`）按本地 DFP 和时间构造明文 `1 + selected56hexDFP + 1 + uppercaseHex(epochSeconds)`，AES-128-CBC/PKCS7 后 Base64；已有实现为 `mtgsig/local_identity.py`。本地候选不等于任意有效的服务端 XID。
- `-initXIDCache`（`0x347f3c`）读取持久键 `DFPXID`、`expireXIDTimeDate` 并检查过期，选择缓存或本地候选。
- `+xidReportDataHandle:`（`0x3476fc`）经回调 `0x3477f8` 更新 `setStatic_dfpXID:`（`0x348314`）。当时完整过期换算待追闭；后续在 `0x38aa80` 证明 interval 以分钟计，从本地回调时刻计算 expiry，详见新报告。

抓包链经过严格收敛：按响应 `times.end` 到后续 `requestBegin` 排序，并要求两端非空 uuid/csecuuid 相等。`evidence/captures/完整版新设备注册登录.chlsj` 的 flow 185 返回结果与该设备后续 **44 条**签名 a7 逐字一致。另三次上报缺少可独立匹配的设备 ID，不计为已证明的同设备链。此前初步统计的“四组同设备”以本次严格筛选为准；缺设备 ID 不等于没有回填。该历史设备也不是本轮 #136。

## 其他字段真正从哪里来

| 字段 | 来源 | 更新边界 |
| --- | --- | --- |
| appsession | 本地 SAKStatisticsSession 生成 | 会话 getter 按缓存/闲置条件重建；不逐请求随机改，不是服务端返回 |
| a5.b7 | SDK 单例首次构造时取本地 epoch 秒 | 同单例保持，不等于每次请求时间；与 appsession 重建不是同一事件 |
| a3 和配套 salt | 默认 provider 或 Horn 配置 | 读取/应用配置后更新，不能只改 a3 数字；接收配置、缓存配置、活动 provider 重载是不同步骤 |
| a10 的 N | SDK 初始化调用系统 rand | 输出 3,N，N 范围 1–254，同 SDK 实例保持，不是请求次数 |
| a7 | 本地 fallback 或 fingerprint 响应 data.result | 成功上报后使用返回值；当前店铺链尚无自动上报刷新 |

### appsession

当前镜像中的 `SAKStatisticsSession -sessionPrefix`（`0x2bf5d18`）读取本地键 `com.sankuai.statistics.sessionPrefix`；缺值时通过 CFUUIDCreate / CFUUIDCreateString 生成并保存前缀。

`-createSessionID`（`0x2bf5e44`）使用格式 `%@%ld%d`：

```text
persisted_uuid_prefix
  + decimal(trunc(NSDate.timeIntervalSince1970 * 1000))
  + decimal(arc4random() % 1000)
```

随机尾数不补零。getter `-appSession`（`0x2bf6054`）在缓存为空或与上次访问相差超过 1800 秒时调用重置；`-resetAppSession`（`0x2bf60ec`）含距上次创建不足 10 秒时抑制重建的逻辑。当前未完成从业务 HTTP header 赋值到该 getter 的新运行 trace；字符串格式相符不能替代这段运行证据。

### b7

`0x2fe1d0` 通过 dispatch_once 获取单例；首次构造 `0x2fe210` 取 NSDate.timeIntervalSince1970，经 NSNumber numberWithDouble / integerValue 得到整数秒，在 `0x2fe294` 保存到分配的 8 字节对象，全局指针为 `0x4f0b338`。

a5 构造链 `0x2f6b20` 取单例，`0x2f3cbc` 附近解引用，`0x2f3c78` 附近构造 JSON 数值，`0x2f2c10` 附近插入 b7。键名编码位于 `0x341282c`，seed=0x38、长度2，逐字节 XOR `(seed + 3*i)` 解出 b7。

不能把这个单例与 `NativeBridge.initDateTime` 等同。本轮新材料 b7 已变，但 a9 的 `2[1]` 仍是较早时间，说明所有所谓“启动时间”不能被统一改为同一个当前时间。

### a3 / provider

provider 对象 +0x58 默认值为 20。Horn `/horn_ios/mergeRequest` 返回 `SAKGuard_Dynamic_Risk.data.customer.sakguard_key_enc_salt`；解密配置得到 a3 与 salt。已观察 host 包括 `horn-hk.mykeeta.com`、`h-eu.mykeeta.com`。

已定位 callback `0x3679b8` → handleDynamicResult `0x367d74` → storage `0x364e98`，缓存键 `sakguard_dynamic_enc_salt_config_key`；初始化从存储读取 `0x364f90`，在 provider `0x30c454/0x30c490` 应用。已有真实启动观察先从存储激活 25，之后 Horn 成功回调同值写入，观察窗口内未再次激活 provider。`mtgsig/provider_config.py` 已有解码实现，日常采集的完整动态刷新链未接通。详细历史证据见 `NATIVE_FIELDS_20261001.md`。

### a10

原生 `0x2f0b9c..0x2f0bd8` 为：

```c
srand((unsigned int)time(NULL));
N = rand() % 254 + 1;
// 保存到全局 0x5015570，后续签名输出 "3,N"
```

这是 SDK 初始化随机值；与 appsession 的 arc4random()%1000 不是同一个生成器。此前真实启动记录已验证实际 rand 输出和后续签名，本轮做静态复核。Python random 不等价于 Darwin libc rand，不能宣称仅用同种子就完成原生逐字对拍。

## 24 次实测及其限制

范围：#136；Clash `http://127.0.0.1:7897`；店铺 `159490763`；从该店主菜单发现的同一个 render 菜品目标。24 次均计入本地请求用量。实验独立保存材料，不替换生产账号材料，不解除冷却或恢复采集批次。

新材料基线为 a3=25、signing profile=legacy、a10=3,75、b7=1791042171。旧材料对应 a3=20、default、3,16、1790945171；登录 token、userid、UUID 相同。以下“旧字段”均指该账号自己的旧观察，不是其他账号字段。

| 在新材料基础上的修改 | render 结果 | 恢复/对照 |
| --- | --- | --- |
| 不修改 | HTTP200/code0，有目标数据 | 实验中多次基线成功 |
| 只换旧 a7 | 200 | 其余会话字段保持新材料 |
| 只换旧 appsession | 200 | 其余会话字段保持新材料 |
| 只换旧 b7 | 两轮均 403 | 各自恢复均 200 |
| 只换旧 a10：3,75 → 3,16 | 403 | 恢复 200 |
| 整套旧 provider：25/legacy → 20/default | 403 | 恢复 200 |
| 只把 a3 25 → 20，仍用 legacy | 403 | 恢复 200 |
| 旧 b7 + 旧 a10 | 403 | 恢复 200 |
| 旧 b7 + 旧 a10 + 旧 provider | 403 | 恢复 200 |
| a7 首字符改动，重新签名 | 200，有目标数据 | 恢复 200 |
| 完整后台旧材料，包括原 host/headers/签名状态 | **200，有同一目标数据** | 最后新材料基线同样 200 |

所有请求按最终字节重算签名，24 条完整 a2 本地校验相等，保存的响应哈希也全部通过核对。变体与恢复请求正常推进 b2/b17；重复 b7 对照的 a5 仅 b2/b17/b7 不同，a9 明文相同。a10/provider/a3/a7 对照的 a5 仅正常 b2/b17 不同，a9 明文相同。

这些是自生成请求的一致性检查，不是本轮每个变体与手机原生签名的独立对拍。部分成功响应哈希不同，且确认返回目标菜品；这不能证明服务端完全没有缓存。旧 a7 和变造 a7 在该目标成功，也不能证明其他接口、状态及未来请求都不校验 a7。

尤其不能从“新材料混入旧 b7 后 403”推出“旧 b7 过期”或“所有账号必须使用某个 a10”。完整旧材料也成功，意味着跨会话组合实验没有单独证明历史 403 的根因。历史失败缺少完整出站材料，无法还原当时全部条件。

首个 b7 拒绝曾被实验报告误归为菜单不完整，已依据原 HTTP403 修正为 rejected，并保留 classification_note；仅修报告分类，没有改原始响应或为此重复请求。

## 证据与复核入口

- 实测汇总：`exports/field-lifecycle-20261003/results.json`；离线核对：`verification.json`。
- 严格 a7 抓包时间/设备链：`exports/field-lifecycle-20261003/a7-capture-chain.json`。
- 回填/重载验证：`exports/field-lifecycle-20261003/a7-handler-validation.json`。
- 私有实验代码及逐次原始请求/响应：`.private/field-lifecycle-20261003/`；此目录含身份材料，不进入部署白名单或对外报告。
- 只离线复核可用 `.private/field-lifecycle-20261003/audit_results.py`、`capture_sources.py`；不要为核对报告重新运行联网 experiment.py。
- 原生方法表与反汇编：同目录 `static-methods.json`、`0x*.asm`、`appsession-stubs.asm`。镜像为 `.private/protocol-audit/current-main-image.bin`，SHA-256 `194747e820db2102408082b0670daa45fc066fb08e0606a341dc63896058130c`，Mach-O UUID `3fb544966dc03ccca41b9055fc509adf`。

本轮真机 remote 连接未运行，USB 附加返回 `module not found at "/usr/lib/frida/frida-agent.dylib"`；没有修改设备环境或重启 App。静态复核使用此前已经与运行构建核对过的镜像，既有真实启动证据单独引用，不把此次静态分析声称为新的真机 trace。本轮没有修改生产采集代码。
