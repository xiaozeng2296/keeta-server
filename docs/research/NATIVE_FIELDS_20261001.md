# 2026-10-01 原生签名字段观察

> 历史原生证据：文中工具/命令对应采样版本，未随精简运行包保留。当前入口见 [协议指南](../PROTOCOL.md)，旧实现可从 [整理记录](../MIGRATION.md) 的固定提交追溯。

本次使用 USB 手机的当前 Keeta 进程，观察签名装配与一次正常 SDK 初始化，没有替换签名结果、强制写 a3 或重置账号。当前 App 为 3.12.500、CFBundleVersion 18565、SDK 5.21.10、iOS 16.0.2。Mach-O UUID 为 `3fb544966dc03ccca41b9055fc509adf`。所有下述地址都是该镜像的 RVA。

## 已验证的数据流

`+[SAKRequestSignatureProcessor signaturedWithMutableURLRequest:]` 调用 `-[NativeBridge call:withParam:]` 的命令 8，最终由 cJSON 装配 mtgsig。先观察 Objective-C 字符串出口，再通过单次签名的调用汇总定位 cJSON 创建/插入函数，最后回溯每个整数的读取点。没有把旧二进制的偏移直接作为当前证据。

| 字段 | 创建/插入调用后的返回 RVA | 来源 |
|---|---|---|
| a0 | 0x2f78dc / 0x2f8104 | 当前格式字符串 2.5 |
| a3 | 0x2f7620 / 0x2f8134 | provider getter 0x30c768：`ldr w0,[x0,#0x58]` |
| a6 | 0x2f7f44 / 0x2f817c | 0x31682c：原子读取全局 0x5015564 |
| a10 | 0x2f8090 / 0x2f81dc | 0x2f7ae4 的字面量 3，加全局 0x5015570 |
| x0 | 0x2f8584 / 0x2f81f4 | 0x2f857c 的 `fmov d0,#2.0` |

### a1：当前主 App 的 ak 配置

`NativeBridge.init` 在 `0x30e1c8` 调用 getter `0x2fe2d8`，把其返回 NSString 转成 C string，于 `0x30e268` 作为第二参数传入 provider 初始化函数 `0x30c454`。当前 getter 的选择分支读取 `NSBundle.mainBundle().infoDictionary()` 的 `ak`，另有 `akd` 分支及内置默认值。

真机读取结果：`use_bundle=1`、`alternate_bundle=0`；getter、Info.plist 的 `ak` 和原生签名 a1 三者逐字一致，`akd` 与内置默认值均不等于当前 a1。当前 a1 原始 UTF-8 的 SHA-256 为 `f7454e72f6a832af5c5677aa9e075b753d497417b64e088fbbbb20d172169f22`。这里只确认当前构建选中了 ak，没有推断其他构建始终选择相同分支。

这闭合了当前 a1 的应用配置来源，不支持“每设备唯一 UUID”的旧说法；其原始字节继续参与密码派生，不能因它不是设备 ID 就替换。

### a3：默认配置与动态配置

构造器 0x30c408 分配 96 字节 provider。0x30c438/0x30c43c 将 20 写入对象 +88。随后 0x30c490 的配置处理调用返回 1，同一成员变为 25。签名 getter 直接读取此成员，因此 a3 的直接来源就是 provider 参数。

启动事件的实际顺序：

```text
provider constructor: +88 = 20
provider config:      before=20, after=25, accepted=1
mtgsig:               a3=25
```

重启前同一 App/build 输出 a3=20/default。不能由这次启动观察倒推前一进程为何没有使用配置 25；后续读取、载荷与时序证据见下文，前一会话未记录的初始化状态仍不能补猜。单次读取 NSUserDefaults 的 `sakguard_dynamic_enc_salt_config_key` 返回空，不能据此断言整个 App 没有配置，实际配置处理已执行成功。

后续启动再次观察到同样的 20→25。`NativeBridge.init` 在 0x30e1a8 调用配置读取函数 0x364f90，把结果转为 C 字符串，再在 0x30e268 传给 provider 初始化函数 0x30c454；初始化函数进入 0x30c490。捕获的配置是 88 字符 Base64，解码后为 64 字节 AES-CBC 密文；解密后是包含 `a3` 和 `salt` 的 JSON。两个入口的配置字节一致；a1 参数是另一条 36 字节 C 字符串。原始载荷单独保存在私有证据中。

配置读取链已进一步闭合：`SAKGuardDCDeviceInfo.sharedManager().storage()` 实际返回 `CIPStorageCenter`，调用 `stringForKey:userDefaultsSuiteName:`，key 为 `sakguard_dynamic_enc_salt_config_key`，suite 参数为 nil。再次从这个入口读取，与初始化捕获的配置逐字相等，SHA-256 为 `f6c2238a3fc9ae512a66f5cb2390a5bcc6f3a94e63027469ca576a2e8d6a924f`。所以不能绕过 SDK storage 包装、直接用标准 NSUserDefaults 的空结果判断配置不存在。载荷内部解析已由下述独立对象实验确认；后续同次正常启动已观察到先读取并加载 25，再发生 Horn 回调及同值写入，详见“同次正常启动的完整时间线”。历史 20 会话未记录初始化入口，不能据此倒推唯一故障原因。

`protocol_watch.py native` 现记录该存储配置的 SHA-256 和活动签名字段；`audit/compare` 会在同 App/build 的配置哈希改变时要求复核。存储配置与当前 provider 是否已同步是两个状态，不因哈希相同就假设当前 a3 必然相同。

配置加载后读取真实 provider：+88=25，原生 +72 的 16 字节 salt 配合 `(25+11)%36=0` 可复现其 mask。项目 legacy profile 的另一组有效 salt/shift=12 也生成同一个 mask。两者是本次 a1 下的等效表示，不能把离线等效参数 1 称为原生实际 parameter。配置数据、mask 和 a1 不写入这份公共报告；摘要仅保留盐的 SHA-256。

### 动态配置的实际编码与验证

编码链为 `JSON UTF-8 → PKCS#7 → AES-128-CBC → Base64`。AES key 来自当前 SDK 算法常量表的 `k0.k1`，已与项目 `DEFAULT_LOCAL_XID_PROFILE.key` 逐字节比较；IV 是 ASCII `0102030405060708`。这里复用的是已验证的常量，不代表此存储值就是 `/v1/scfg` 报文。

当前解密结果的结构是 `{"a3": integer, "salt": 32 个十六进制字符}`。`a3=25` 与对象 +88 一致，salt 解成 16 字节后与对象 +72 一致；盐的 SHA-256 为 `6fa71bf428cf9749caf0e70e0a1b3e7b12293b19c09175d49715d08077591882`。原始 JSON 保留顺序和空格后，可逐字节重编码回存储密文。

对每个测试新分配 96 字节对象，写入默认 salt 和参数 20，仅调用 parser `0x30c490`，没有调用会覆盖 singleton 的构造器。13 个原生案例证明：

- 原配置与重新序列化的配置都返回 1，得到参数 25 和同一 salt。
- 只改 a3 为 24、20、0、36，返回值均为 1，对象参数跟随变化；只改 salt 一字节，对象盐跟随变化。
- 空字符串返回 1，保留默认参数/盐；缺 a3、缺 salt、盐长度不足返回 0。
- a3=-1 返回 1，参数保留 20，但 salt 仍更新；a3 为字符串 `"25"` 返回 1，参数变为 0。不能只用返回码判断配置语义有效。
- 所有案例的活动 singleton 96 字节与 a6 前后都未改变。另一个全合成 salt/a3 案例也通过，已作为公开单元测试向量，未包含账户材料。

新增 `mtgsig/provider_config.py` 严格接受非负 32 位整数及 16 字节盐，拒绝重复键、额外字段、类型错误、非规范 Base64、错误 padding。它不会模仿上述异常 JSON 的宽松类型转换。`None` 表示没有观察资料，不等同于原生空字符串默认配置。

`protocol_watch.py native/audit` 会解码配置，输出参数、shift、盐摘要，并验证同一容器内配置是否匹配签名 a3/a5。已知命名 profile 失败时，审计可使用解出的真实参数验证 a5、完整 a2，并独立尝试 a9；a9 的已有缓存配置仍单独检测。`mtgsig.signer.k2buf/decode_a5/compute_a2` 接受显式 `ProviderConfig` 对象供对拍使用。本次没有自动迁移账户中的命名 profile。

### 动态配置的写入入口

当前运行代码的配置 key 引用还定位到 `0x368170`。所在处理函数为 `0x367d74`，内部日志标签是 `handleDynamicResult`；从动态字典取 `sakguard_key_enc_salt`，解密后读取整数 `a3`，在 `a3 >= 21` 时把原始密文交给 storage 写入函数 `0x364e98`，key 为 `sakguard_dynamic_enc_salt_config_key`。因此“parser 能接受参数 0/20”不等于动态下发流程会保存它们。

这一段为当前内存代码、相对分派表及 CFString/selector 解析的静态证据；没有伪造配置回调去写 App 存储。回调 block invoke `0x3679b8` 读取 block+0x20 的配置类型，匹配 `SAKGuard_Dynamic_Risk` 或 `SAKGuard_Dynamic_Risk_Test` 时，在 `0x367bc0` 调用 `0x367d74`。这两个名称已从当前运行镜像的 CFString `0x4e8a770/0x4e8a850` 读取确认。

### Horn 下发与后续请求的时间证据

三份已有 Charles 抓包的 `/horn_ios/mergeRequest` 成功响应均含
`$.SAKGuard_Dynamic_Risk.data.customer.sakguard_key_enc_salt`。密文 SHA-256 与当前 storage 值一致，解密参数均为 25，salt 也一致。

| 抓包 | 配置 flow 下标（从 0 开始） | 配置响应结束后开始发送的原生请求 | 这些请求的 a3 |
|---|---:|---:|---:|
| 从app初次打开到登录被拦截.chlsj | 166 | 17 | 全部 20 |
| 新机之后尝试登录.chlsj | 38 | 66 | 全部 20 |
| 完整版新设备注册登录.chlsj | 12 | 83 | 全部 20 |

前者 host 为 `horn-hk.mykeeta.com`，后两者为 `h-eu.mykeeta.com`。统计严格使用带时区的 `times.requestBegin >= 配置响应 times.end`，不用并发 flow 的数组顺序，也不用设备 a4 与抓包时钟比较。若同一类型再次下发，以新响应结束时间截断前一观察窗口。

这证明收到参数 25 后仍有携带 20 的请求发送，不能独自证明 App 已处理回调、写入存储或重新初始化 provider；已签名请求也可能延迟发送。已有启动观察另外证明存储配置可以在初始化时把默认 20 改为 25。两种证据分别保留，不倒推历史会话中未观察到的写入时刻。

`protocol_watch.py config` 将这一检查做成可重放命令，只输出参数、配置/盐哈希和时序计数。原生存储→签名绑定仍使用 `native/audit`。缺时间戳、没有下发响应或没有后续签名时报告 incomplete，不用数组顺序补猜。

### a10：独立的启动随机参数

初始化片段 0x2f0b9c 至 0x2f0bd8 依次调用真实系统 `time`、`srand`、`rand`，计算余数后写全局 0x5015570。已通过当前导入表确认函数名，未仅凭相邻调用猜测：

```c
srand((unsigned int)time(NULL));
N = rand() % 254 + 1;
// 签名时读取保存的 N，格式化为 "3,N"
```

启动观察为 `time=1790906627`、`srand` 同值、`rand=636883637`、写入 `228`。独立算术复核 `636883637 % 254 + 1 == 228`，随后三条签名均为 `3,228`，b2 为 29/30/31。前一会话为 `3,245`，b2 为 117/118/119。此后通过系统 UI 再启动的会话为 `3,231`。

公式的范围是 1–254。不能用 Python 的随机实现替代 Darwin libc 的 `rand` 后宣称相同时间种子可逐字重现；现有会话直接取样本 N 即可，也不能把旧实现缺材料时回退的 1000 当成原生初值。

### a6：累积状态位，非设备 ID

0x31682c 用 LDAR 读取整数，多个写入点以 LDAXR / ORR / STLXR 累积位值。当前所有原生采样为 0。已定位的位与代表写入点如下，表中不为未知位编造业务名称：

| 位 | 代表 ORR RVA | 当前可确认条件 |
|---|---|---|
| 0x01 | 0x3168d4、0x316bbc | 在已定位两条状态检查路径中，写入 0x02 后继续写入此位；因此同一条件累计成 0x03 |
| 0x02 | 0x3168a4、0x316c58 | 资源对象非空，内部状态 S 位于 0x4e81fc0，`S != 0x70b && (S & 8) != 0` |
| 0x08 | 0x3926ec | 内部资源开关启用，XBT 加载函数 0x392710 返回空，构造结果标记不可用 |
| 0x10 | 0x310fc4 | PIC 初始化函数 0x311054 返回 false；其路径包含必需配置字符串、图片解码和 PIC 数据校验 |
| 0x40 | 0x311ce8、0x312cb0、0x312e80 | 字符串/int/double 读取包装器调用 0x311e28 后得到 nil；空 key 或类型不匹配有另外的回退分支，不能笼统归为此位 |
| 0x80 | 0x312b7c、0x313e08、0x313f84 | `.PIC` 头/内容校验失败，或关联资源重建/查询路径缺少所需对象；多个分支共享此位 |
| 0x100 | 0x2f0af4、0x3927d0 | PIC/XBT 兼容标签不相等，或者 `.XBT` 头/内容校验失败 |

所有地址均依据当前运行镜像解出的相对跳转表；没有把反编译猜测作为观察结果。各位描述限定于已经追到的写入者，尚未证明是整个镜像的完整枚举。S 的一个实际写入者与资源绑定校验已经闭合，见下节；仍未为 `0x70b` 等其他状态编造语义。

在隔离 Unicorn 内执行复制的原始 `0x316b5c` 及其真实分派器，6 个合成状态验证：S=8/对象存在时返回 1，a6 从 0 变 3；原 a6=64 时变 67；对象为空、S=0 或 S=0x70b 时不改位。没有修改真机全局状态来制造这个结果。当前真机 S=0，a6=0。

`.PIC` 验证器 `0x314578` 和 `.XBT` 验证器 `0x393378` 都检查 28 字节头：magic 位于 +0，格式整数位于 +4，payload 长度位于 +8，兼容标签位于 +16，Adler-32 位于 +20，payload 从 +28 开始。PIC 格式整数为 400，XBT 为 1。导入 `0x31d73b0` 解析为 `libz!adler32`，不是 CRC32。验证成功把 +16 的标签复制到 PIC 对象 +0xec、XBT 对象 +0xc；启动时比较这两个成员。

真机独立对象的 10 个合成头测试中，两类有效数据均返回 1 并复制标签 123；分别只改 magic、格式、checksum 或正文一字节，都返回 0 且保留初始标签。所有测试的活动 a6 未改变。当前真实两资源标签同为 `0xea243b5e`（uint32 3928243038）；它是用于一致性比较的标签，未证明是递增版本号。

`native --trace-fields` 现记录 `resource_status` 与两个 `resource_tags`；`audit/compare` 会发现同 App/build 的资源标签变化。0x80/0x100 至少包含资源完整性/兼容性分支，不能把非零统一解释为越狱或账号失效，也不能把 0 当成环境无风险的证明。

### 当前主镜像的 a6 直接引用范围

从本次真实进程崩溃报告的 `procPath` 取得主 Mach-O（88,037,264 字节），UUID 与运行进程一致；SDK 的 `0x2d0000..0x430000` 与先前运行内存快照逐字节相同，差异为 0。主镜像 SHA-256 为 `194747e820db2102408082b0670daa45fc066fb08e0606a341dc63896058130c`。

扫描所有标记为指令的 section，共 13,614,607 条指令，排除 FairPlay 的 4 KB 加密页（1,024 条）。a6 所在页有 630 处引用，其中识别到 14 处直接 ADRP+ADD 构造 `0x5015564` 地址，全部位于上述已核对 SDK 区域：

```text
0x2f0ae4 0x310fb8 0x311cd8 0x312b70 0x312ca0 0x312e6c 0x313df8
0x313f74 0x31682c 0x316894 0x316c48 0x318c78 0x3926e0 0x3927c0
```

这是地址构造数量，不是 14 种状态位或 14 个写入者；其中 `0x31682c` 是签名所用 getter，`0x318c78` 是另一读取点，后者用途未扩展解释。扫描没有穷尽计算型指针、间接别名或加密页，不能宣称完整写入者枚举。依据为 `a6-main-image-references.json` 与 `scan_a6_image_references.py`；早期局部扫描的重复候选不能与该统计混用。

### a6 的 0x01/0x02：开发团队与 PIC 资源的绑定校验

当前写入者 `0x31567c` 调用 guard `0x314f40`，在 `0x3156a0..0x3156b4` 执行 `S = guard_ok ? 0 : 8` 并原子写入全局 `0x4e81fc0`。下游状态检查再按前述条件累计 `a6 |= 3`，不是把 S 直接当作 a6。

guard 的当前成功路径已经通过真机观察闭合：

```text
当前 Mach-O 的 LC_CODE_SIGNATURE / entitlements
  → 解析 com.apple.developer.team-identifier
  → CC_MD5(team 的 UTF-8)，转为 32 字符大写 hex
  → 0x38cc2c：SHA-256 后再逐字节变换
  → 0x3904d0：转为 64 字符小写 hex
  → 与 PIC 字典的 a3 字符串比较
  → guard 成功；writer 将 S 写为 0
```

**PIC 字典的 `a3` 是资源校验值，不是 mtgsig.a3 的 provider 整数。** `0x3000c4` 的输入构造先调用 `SAKGuardCommon.fetchDebugBundleId`；当前返回 nil，随后使用上述真实 entitlements 路径。不能因 selector 名称包含 BundleId 就把当前校验输入解释为 bundle identifier，也不能把尚未走到的非 nil 分支概括成相同逻辑。

`0x35d600` 定位当前 Mach-O 的 `__LINKEDIT` 和 `LC_CODE_SIGNATURE`；`0x30ab80/0x30ac90` 处理签名 SuperBlob 中的 entitlements。SDK 在内存中加密缓存相关数据。观察到解密后的 XML，以及字符串匹配 `com.apple.developer.team-identifier</key><string>`、分割 `</string>` 和真实 `CC_MD5` 调用。MD5 输入与该 XML 的 team 字段逐字一致，大写输出与 guard 输入逐字一致；实际团队标识及完整 entitlements 只保留于私有证据。

摘要内核 `0x38ccf4`（update）、`0x38ce34`（final）、`0x38cf78`（压缩轮）具有标准 SHA-256 初值、全部 64 个轮常量和 padding；final 输出与 Python SHA-256 一致。外层 `0x38cc2c` 的返回内容则不同。45 个独立合成输入（包括空串、单字节变化和跨块输入）确定了一组等效逐字节映射：`out[i] = ((sha256(input)[i] + A[i]) & 255) ^ B[i]`。固定选取 `A[i] < 128` 后各槽候选唯一，并在未参与拟合的真实团队校验输入上匹配 native 输出与 PIC 的 a3。

该映射是对当前构建的逐字节对拍结果，原 VM 常量编码尚未逐条提取，不能声称已还原它的全部源级实现。`__dynamic_cast` 的 160 次调用来自 VM 对象操作，不是 160 次 SHA 运算。对原生标准 SHA 输出做直接比较会失败，原因是外层变换，不能误报 SHA 内核已换算法。

多次直接调用 guard 都返回 1；没有调用全局 S writer，也没有替换任何返回值。合成摘要测试仅使用新分配的输入/输出缓冲区；活动 provider 的 96 字节、S 和 a6 均未改变。卸载观察脚本后，额外 1 条正常原生签名的完整 a2、a5/a9 往返与存储配置绑定通过。可重放脚本、合成向量和脱敏验证摘要列于公共观察 JSON，原始内容位于 `.private/protocol-audit/`。

## a2 大请求体：16,200 字节边界

最初七份抓包中 a2 为 563/566，失败的三个请求都在 `/fingerprint/v1/app/bio/info/report`，Body 分别为 50,688、49,436、53,388 字节。重新把它们交给当前 App 的原生本地签名器仍可复现差异；合成 512 字节能匹配，32,768/50,688/65,536 字节不能匹配。这一步没有字段 hook、没有发出 HTTP 请求，排除了只因旧抓包损坏而失败的解释。

随后仅在本工具调用签名器的线程观察消息拷贝：`NativeBridge.call:withParam:` 的 operation=8 收到原始 NSMutableURLRequest；函数 `0x2f8648` 经 `0x2f094c` 分别复制两段数据，返回 RVA 为 `0x2f9f44` 与 `0x2f9f5c`。第一段逐字节等于 canonical 请求串加 Body 的 UTF-8 前缀，第二段等于完整签名 payload：

```python
message = canonical_request.encode('utf-8') + body.encode('utf-8')[:16200] + payload_json.encode('utf-8')
```

复制包装器的当前指令和 Mach-O UUID 均经过校验；没有更改传入指针、长度、回调返回值或活动 provider。用观察到的完整两段消息独立执行 HMAC/pass1/pass2，3 个定位样本和 7 个边界样本全部匹配原生完整 a2。

| 输入 | Body 实际字节数 | 纳入签名的 Body 字节数 |
|---|---:|---:|
| ASCII 边界前 | 16,199 | 16,199 |
| ASCII 恰好边界 | 16,200 | 16,200 |
| ASCII 超过边界 | 16,201 | 16,200 |
| 中文 JSON | 18,011 | 16,200 |
| emoji JSON | 20,011 | 16,200 |
| 中文字符横跨截断点 | 16,205 | 16,200 |
| emoji 横跨截断点 | 16,206 | 16,200 |

截断可以停在 UTF-8 字符中间；不能按 Python 字符数截断，也不能对前缀重新 decode/encode 或插入替换字符。Body 上限不包含 canonical 请求串和 payload；这是**签名消息**的长度处理，实际 HTTP Body 保持原样。

`mtgsig.a2.signing_message()` 统一该行为，`mtgsig/signer.py` 与历史消息生成入口复用；独立验证工具同步原生边界。修复后重新审计：此前未加观察 hook 的 7 条原生大 Body/长度样本全部通过；七份原始抓包的 566 条原生布局也全部通过完整 a2、a5/a9 往返，另外 4 条 x0=4 保持 unsupported。历史失败报告未覆盖或删除，新报告单独记录修复后结果。

`tests/protocol/test_a2_message.py` 保存 7 组真机观察的合成 Body 前缀哈希，不包含账号或设备采集明文；另测字节跨界、签名边界与 payload 绑定。增加这 4 项后相关回归共 67 项通过。证据范围是上述 App/SDK 构建及历史样本，尚未进行新业务请求的服务端验收；升级时需重验这一长度规则。

## Horn 生命周期与失败实验的边界

当前 `SAKHorn.sharedInstace().configFetchers()` 中正式类型 `SAKGuard_Dynamic_Risk` 已注册，测试类型未注册；正式 fetcher 的 block invoke 为 `0x3679b8`。只读取得的 block 类型编码为 `v20@?0B8@"NSString"12`，即返回 void、参数 BOOL 和 NSString。缓存版本为 1324115，缓存的加密配置、SDK storage 和活动 provider 均为参数 25，盐哈希一致。

经正式 `forceRefreshTypeArray:completion:`（completion 为 nil）观察，`last_request_time` 更新，Horn 返回 HTTP 304、load_source=4、无错误码；进入 fetcher 的结果处理，但没有进入上述注册回调、storage 写入或 provider 重载。这是一次窗口内的真实结果，不是所有 304 分支的通解。仅有服务端配置、缓存、storage、provider 的相等快照，不能替代发生过更新的时间线。

公开 `observe-config` 已记录回调、目标 key 的存储读写、provider 初始化/配置处理和 Horn 结果。事件上限 1000；摘要配对同线程嵌套调用，将 active provider 加载与 callback→write 分开计数。UUID/关键指令不匹配时拒绝附加旧偏移。回调期间写入函数返回不证明已持久化到磁盘。

**一次失败实验明确排除：** 私有脚本把 fetcher 原有 block 传给 `getCachedDataForType:callback:`，进程 73893 于 2026-10-02 11:56:09 +0800 发生 `EXC_BAD_ACCESS / SIGSEGV`。栈顶为 `objc_retain`，返回位置为 callback RVA `0x367b7c`，另有缓存异步路径 `0x2b2d078`。这证明该调用组合不安全；当前只读代码/类型核查尚未区分 ABI、block 传递或生命周期原因，不能宣称已证明具体根因。实验脚本顶层已禁用，未重放、未计为配置生效证据。原始崩溃报告保留在私有证据。

恢复时先确认 App PID 为 0，再通过系统 `uiopen` 打开并确认新 PID 74221；只对已确认的新 Keeta 进程执行现有 roothide `jbctl proc_set_debugged`。随后正常字段观察、原生签名及 detach 成功。恢复后 1 条样本的完整 a2、a5/a9 往返和配置绑定均通过，状态为 a3=25、a6=0、a10 会话值 51。3 秒纯被动配置观察没有事件且正常退出；不会因此标为“配置更新成功”。PID 是这次证据，不是下次命令的固定参数。

配置生命周期阶段回归为 63 项通过，包括新增的 10 项生命周期测试；加上 a2 边界测试后当前为 67 项。测试覆盖 304 无回调、跨线程与嵌套关联、未结束/错配事件、失败或非活动 provider、参数/盐差异、事件丢失、显式刷新和中断报告保存。真机崩溃未被用作测试手段。

## 同次正常启动的完整时间线

`startup-configuration-complete.json` 记录 PID 74387 的正常 SDK 启动，窗口 20.31 秒。只观察启动行为，没有主动刷新配置、复用其他 API 的 callback、清缓存或修改 provider。相对第一次 storage 读取的时间如下：

| 相对时间（毫秒） | 事件 | 结果 |
|---|---|---|
| 0 | storage_read / provider_initialize_enter | 读取 88 字符配置；provider 原值为 20 |
| 1 | provider_configure_enter / leave | parser 返回 1，活动 provider 变为 25 |
| 1 | provider_initialize_leave | 参数保持 25；该函数返回 0 不能解释为配置失败 |
| 3541–3542 | Horn apply/check/result | HTTP 304、load_source=5，类型为 SAKHornParamsInfo |
| 3543 | 正式类型 callback_enter | success=true |
| 3545–3546 | storage_write_enter / leave | 写入相同配置，调用正常返回 |
| 3549 | callback_leave | provider 保持 25 |

读取、初始化、parser 入参和写入配置的 SHA-256 均为前述 `f6c2238a…24f`。报告为 `linked_callback_writes=1`、`active_provider_load_count=1`，丢事件、观察错误、未配对事件均为 0。provider 加载发生在回调之前，回调之后窗口内未见重载。卸载 hooks 后同进程的一条正常原生签名完整 a2、a5/a9 往返及配置绑定均通过，随后正常 detach。

因此刷新路径 source=4 与启动路径 source=5 的 304 行为不同；未恢复 source 的完整枚举名称，不为它编造业务语义。写入返回不证明物理落盘，同值写入也不证明一份新配置已经激活。本次没有下发不同值，因此不外推不同参数/盐的热更新规则。

### 观察工具的两次失败及修复

- 首次启动 PID 74331 在安装观察器时被 `OBJC / code 1` 终止，崩溃栈涉及 `_objc_fatal`、`NSObject methodSignatureForSelector:`、`NSBundle initWithPath:` 和 `mainBundle`。原因链对应启动早期校验调用完整 `metadata()`，过早初始化 Foundation。已改为仅解析 Mach-O 内存头的 `imageMetadata()`；完整元数据在正常启动后读取。系统恢复后 PID 74353 的普通签名验证通过。失败报告和原始 `.ips.forced-by-frida` 崩溃证据均保留。
- 接着 PID 74366 已正常启动并收到回调，但四个配置摘要出现指针类型错误，报告保持 `incomplete_observation`。摘要改用显式 UTF-8 buffer 和准确字节长度调用 SHA-256，不把 `NSString.UTF8String()` 桥接对象直接当原生指针。之后才得到上述无错误的完整窗口。

`tests/test_protocol_probe.js` 的 4 个案例覆盖：不依赖 Foundation 的早期安装/卸载、未知 UUID 拒绝、错误指令拒绝，以及非 ASCII/emoji/内嵌 NUL 的 UTF-8 摘要。它们与 Python 的 67 项回归分开计数。失败报告没有改写成成功，后一次验证也不能消除早期实验曾终止 App 的事实。

复现完整启动使用私有 `observe_startup_configuration.py --out <新报告路径>`，脚本会重启选定 App，固定连接参数仅适用于本次已核实的 USB 环境。日常版本检查使用公开 `device/native/observe-config`，无需为检查版本重复启动。原始脚本、失败记录、成功报告及签名审计的哈希见观察汇总。

## 复现与升级定位

1. 用 `protocol_watch.py device` 和 `release` 记录版本；正常打开 App，再用 `native --trace-fields` 观察当前状态。该命令不重启、不发送请求，未知 UUID 或关键指令不匹配会拒绝应用旧地址。
2. 原生字段证据保存在输出 JSON 的 `field_trace`；完整 mtgsig 在 `samples`，属于私有原始材料。`audit` 只输出结构、版本、哈希与验证结果。
3. 要重做启动来源研究，需在启动早期附加：观察 0x30c408 构造器返回、0x30c490 配置处理入口/返回；在时间/随机调用处按返回 RVA 0x2f0ba4/0x2f0ba8/0x2f0bac 过滤，观察 0x2f0bd8 写入前的 w8。不要为了制造 20/25 而修改 provider。
4. 保存启动事件、同进程原生样本和 audit，再与正常 UI 启动后的样本比较。使用过 Frida spawn 的实验进程曾发生 script unload/detach 等待；显式移除启动 hooks 后的配置观察能正常退出，但后续重复附加仍曾超时。结束实验进程并经系统 UI 启动后，普通和带字段观察的 CLI 均有正常退出的验证。工具通过 Frida Cancellable 为每个操作设置期限；真实挂起的 attach 已验证在 3 秒测试期限内返回 `operation=attach / OperationCancelledError`。不能把卡住的退出解释为采样没发生，更不能无限重启重试。
5. 新版重新定位 selector → bridge → JSON 装配 → 字段读取者，再更新 trace 的 UUID 与地址校验。当前 SDK 代码片段位于非加密区域；镜像 cryptid=1、加密页为 0x221d000..0x221e000。旧 `dump/Keeta.dec` 的 UUID 不同，不能用旧反汇编覆盖当前证据。

本次原始实验记录位于 `.private/protocol-audit/`，公共摘要及原始文件 SHA-256 见 [观察汇总](https://github.com/xiaozeng2296/keeta-server/blob/2ec895ea20c0ca273ee036af5dc0d8fed55d1f97/docs/research/PROTOCOL_OBSERVATIONS_20261001.json)。历史 566 条原生布局审计与本次真机采样分开计数。

## USB / roothide 连接要点

本机 Frida 16.1.4 与设备临时服务一致。独立 iproxy 将当前手机的 SSH 22 转到本机 28322，将临时 Frida 27043 转到本机 28343；连接前必须核对 UDID，不能用指向另一台手机的 2222/2223 转发。

此前注入失败因为 SSH jailbreak 命名空间与 App 文件系统不同。App 可见的 `/var/tmp/keeta-agent.dylib` 对应 SSH 一侧 `/rootfs/private/var/tmp/keeta-agent.dylib`；调试服务一侧也有同内容的 `/private/var/tmp/keeta-agent.dylib`。临时服务只把内置 agent 路径等长替换为该路径，并保留原 entitlements 重新签名；没有更改 App 二进制、安装全局 Frida 启动服务或修改其他设备转发。

不要把这个环境修复当成通用安装器。agent、服务签名、目录映射与设备 jailbreak 版本相关；先验证一次 attach、metadata 和正常 detach，再运行采样。当前可复用 `--remote 127.0.0.1:28343`，设备 PID 以 `device` 的本次结果为准。
