# 完整成功抓包：设备注册链与身份生命周期

> 历史研究资料，来源 `codex/keeta-project@6197c528`；保留当时的观测与未完成项，不代表新项目当前状态。当前规则见 [字段状态](../MTGSIG_FIELDS_STATUS.md)，复跑入口及已修正结论见 [离线研究指南](../research/OFFLINE_RESEARCH.md)。文中的旧 `dump/`、抓包及设备路径仅作证据索引，原材料未随仓库发布。

本次只读离线分析 `完整版新设备注册登录.chlsj`（778 条 Charles 记录），不发送请求、
不访问手机、不更改身份。索引为 JSON 数组 **0 起始索引**。下文以本地值 L、服务端值
D/X 的标签表示身份，不公开 UUID、DFP、XID、邮箱、认证或会话材料。

原包 SHA256：`5f218afcfe01a3a1acedee5938753ccf2528e4d2d8603c26553c03d39153013a`。

## 真实请求与区域变化

请求主机取 HTTP/2 `:authority`，其次 `Host`，最后才使用 `flow.host`。
本包登录三步的 `flow.host` 是连接复用主机，实际 `:authority` 为 `passport-eu.mykeeta.com`。

| 索引 | 请求主机 | 路径/作用 | 结果 |
|---|---|---|---|
| 0 | uuid-eu.mykeeta.com | `/uuid/oversea/ios/register`，requiredId=1 | HTTP200/code0，返回 unionId |
| 1 | uuid-eu.mykeeta.com | 同路径，requiredId=4 | HTTP200/code0，返回另一 unionId |
| 2 | i18n-eu.mykeeta.com | `getRegionConfigs` | HTTP200，初始区域 GG |
| 9 | mtpush.mykeeta.com | `/sdkapi/newreg` | 返回 push token P1，country=GG，无 apnstoken 字段 |
| 14 | pikachu.mykeeta.com | `/fingerprint/v1/info/report` | code0，返回 XID X1 |
| 36 | pikachu.mykeeta.com | `/v5/sign` | code0，返回 DFP D1 |
| 53 | i18n-eu.mykeeta.com | `getCompassConfigs` | HTTP200 |
| 65 | fooddelivery-eu.mykeeta.com | `getOpenServiceRegion` | HTTP200，初始 GG 上下文 |
| 117 | i18n-eu.mykeeta.com | `currentLocalInfo` | 返回 BR/BRL，cityId=102302389，districtId=102317211 |
| 132 | pikachu-eu.mykeeta.com | `/v5/sign` | 切区后再次注册，返回 D1，**与 #36 相同** |
| 176 | fooddelivery-eu-3.mykeeta.com | `getOpenServiceRegion` | BR 上下文 |
| 183 | pikachu-eu.mykeeta.com | `/v1/scfg` | code0，配置密文可离线解密 |
| 184 | pikachu-eu.mykeeta.com | `/fingerprint/v1/app/bio/info/report` | code0 |
| 185 | pikachu-eu.mykeeta.com | `/fingerprint/v1/info/report` | code0，返回新 XID X2，**与 X1 不同** |
| 201 | push-eu.mykeeta.com | `/sdkapi/newreg` | country=BR，增加 apnstoken，返回 P2，**与 P1 不同** |
| 270 | pikachu-eu.mykeeta.com | `/v5/device-info` | code0 |
| 321 | i18n-eu.mykeeta.com | `currentLocalInfo` | 同区域/城/区，locale/lang 从 zh 变 en |
| 342 | pikachu-eu.mykeeta.com | `/v1/scfg` | 第二次 code0 |
| 431 | pikachu-eu.mykeeta.com | `/v5/device-info` | 第二次 code0 |
| 584 | fooddelivery-eu-3.mykeeta.com | `confirmProtocol` | HTTP200/code0 |
| 585 | passport-eu.mykeeta.com | `userriskcheck` | HTTP200，后续进入 signup 分支 |
| 589 | passport-eu.mykeeta.com | `emailsignupapply` | HTTP200，返回 email/serialNumber |
| 599 | pikachu-eu.mykeeta.com | app bio report | code0，发码与提交之间又上报一次 |
| 601 | passport-eu.mykeeta.com | `emailsignup` | HTTP200，返回顶层 user |
| 604 | fooddelivery-eu-3.mykeeta.com | `confirmProtocol` | 登录后的另一请求 |
| 766 | pikachu-eu.mykeeta.com | app bio report | code0，登录后继续上报 |

以上是包内观察到的阶段，不等于每一路都是发码的必要前置。
`currentLocalInfo` 两次返回的 timeZone 都是 `GMT+00:00`，不能根据 BR 自行改成推测时区。
登录的 `tk_context_plain` 解码后为 `{"a1":"BR","a2":"5","a3":"4"}`。
a5.b22 和 app bio.regionPath 都记录 `GG → BR`，数值是启动后累计毫秒；
本次样本值为 145 和 12419，重建时应使用本会话事件时间，不复制这些历史数值。

## 并发及先后关系

数组索引、请求创建、线上实际发送与响应完成是四个不同时间点。
本包不能解释成固定的 `OneID → sign → newreg → info` 串行链：

- OneID #0/#1 几乎同时创建，共用 localId/sessionId/IDFV。requiredId=4 (#1)
  在 20:19:28.615 发出，requiredId=1 (#0) 在 28.632 发出，分别在 28.955/28.971 完成。
  requiredId=1 请求在 requiredId=4 响应完成前已经发送，不依赖其返回值重新构造。
- newreg #9 在 20:19:28.435 发出，在两次 OneID 完成前结束。
- info #14 于 20:19:29.148 发出、29.474 完成；sign #36 于 29.245 创建、29.893 发出。
  #36 签名仍带初始本地 XID。其请求创建早于 info 响应完成，因此不能仅以线上
  requestBegin 排序，就断言 App 没有应用服务器 XID。
- #183/#184/#185 都在 20:19:41.632 创建，实际发送也十分接近，是切区后的并行上报。

时间均使用抓包原时区 -07:00。顺序执行的复现可以更简单，但不能将其称为精确复刻原生调度。

## 本地身份、下发与复用的确证

93 个原生 mtgsig（含 a0）具有 1 个 a1、3 个 a7、2 个 a8、9 个 a9 密文。
Web/notapp 路径上的另一类签名没有混入此统计。

| 阶段/核验 | 结果 |
|---|---|
| #3 起的初始 a8 | 通过 `decode_local_dfp` 的布局和 CRC32 校验，记为 L8 |
| #3 起的初始 a7 | 通过 `decode_local_xid` 解码，记为 L7 |
| L7.source_dfp_id == L8 | true |
| L7 秒时间 == L8 毫秒时间整除 1000 | true |
| L8 内部 UUID == OneID IDFV / mtgsig.a1 | 两项均 false，属于不同标识 |
| #14 response.data.result | X1；与 L7 不同 |
| #36 response.data.dfp | D1；与 L8 不同 |
| #47 起的签名 | a7=X1、a8=D1 |
| #132 response.data.dfp == #36 response.data.dfp | true，仍为 D1 |
| #185 response.data.result == #14 response.data.result | false，变为 X2 |
| #259 起的签名 | a7=X2、a8=D1 |
| #585/#589/#601 的签名 | 全部使用 X2/D1；a1 也不变 |
| 服务端 D1/X1/X2 是否仍匹配本地 L8/L7 解码格式 | false |

OneID 的 requiredId=4 响应与登录 B.I40、header.csecuuid、scfg.uuid 精确相等；
requiredId=1 响应与 header.pragma-unionid 精确相等，两类返回值不能混用。
两次 newreg.deviceid 均等于 OneID 请求 IDFV 和 risk B.I20，不能用 IDFA 代替。

这个包确实证明**同一会话、同一设备状态下，切换区域路由后再次 sign 可以得到相同 DFP**。
它没有提供“只改变一个硬件字段”的试验，无法推出任意相近设备一定下发同一个 DFP，
也不能确定服务端匹配字段或权重。

## 解密范围

- 所有 93 份原生 a5：`default` 配置解密并解析 JSON 成功。
- 9 种原生 a9：均命中 `twofish`，通过 padding、CRC32、完整 zlib 流校验。
  最早两种 a9 扩展数组有 19 项，之后为 23 项；基础数组均 16 项。
  `a9["2"][16]` 在所有 9 种 a9 中相同，长度 34，符合本会话 collector 缓存复用。
- 登录 #584/#585/#589/#601/#604 的 B fingerprint：均成功解成 45 项 I-series。
- 两次 scfg.data 及两份 data.resStr：都可解密。request.dfpid 等于当次 a8，
  request.uuid 等于 OneID csecuuid；userid 为未登录 `-1`，city **为空串**。
  返回 applist_config 为空、version_code 为 `1`；没有把配置字段名中的 key 当作密码密钥。
- 9 条原生 A-envelope（#14/#36/#132/#184/#185/#270/#431/#599/#766）具有同一个
  128 字节 RSA part1。这是封装材料复用证据，不是明文相同。
  读取现有注册工件 32 份 profile，得到 3 把不同会话密钥，分别按 default/legacy
  对本包 a1 派生并重算 RSA，**匹配数为 0**。这些 A 正文当前没有匹配密钥，
  不声称已解密，也不从相邻 a5/a9 猜正文内容。

## 与当前协议画像的差异

对照 `dump/registration_session/login_token_remaining/03/profile-after.json` 和
`identity-after.json`（序号 193）：

- 成功包和当前协议都是 iPhone12,1 / iOS16.2 / 828×1792 / 6 核 / arm64e / App 3.12.401。
- 本包 risk #585 的 B 指纹与当前协议 **33/45 项相同**。不同项为
  I36/I23/I18/I37/I19/I25/I44/I39/I14/I20/I40/I41：涉及设备名、存储、IDFA、
  安装/首次启动/开机时间、网卡 IP、CPU、当前时间、IDFV、OneID 和内存快照。
- IDFA/IDFV/OneID 三项均不同；签名 a1 相同，a7/a8 均不同。
  与另一份 `发送验证码并成功登录.chlsj` 的成功 #14 相比，34/45 项相同，
  IDFA/IDFV/OneID/a7/a8 也全部不同。相同硬件外观没有导致这几份样本使用相同 a8。
- a9 基础数组与当前协议 15/16 项相同，扩展数组 12/23 项相同。
  不能只更新可见 UUID 就称为完整新设备，现有协议仍复用明确来源的硬件和环境观测。
- a5 的 b1.33（环境检测对象）、b1.55（数字指纹）、b1.58（采集时间）与当前协议不同；
  a5 的 b7/b8/b9、b22 等会话/区域字段也不同。单个不同项不能归因为服务端拒绝原因。
- 当前已验证协议链是 HK；此成功包是 GG→BR，且包括两次 sign/info/newreg、
  两次 scfg/device-info。注册下发链需结合区域回调继续推进，而不是把同名路径视为重复后删除。

## 成功包自身的字段变化例外

#584/#585/#589 的 I18/I20/I40 相同，并满足 I18=form.device_id、I40=header.csecuuid。
但不能扩大为本包所有步骤均满足该绑定：

- #601 最终 signup 的 I20 与 risk 的 I20 不同（不是大小写差异，仍为 36 字符）；
  I18/I40 与 form/header 仍一致，签名 a7/a8 没变。
- #604 登录后 confirm 的 I18 为 7 字符，I40 为空，不再等于 form.device_id/header.csecuuid；
  I20 恢复为 risk 时值。

这些是解密得到的观测，原因尚未确认。它们不是需要故意制造的协议规则，
也不能作为“多个指纹面无需保持一致”的普遍证据。

## 重放检查方法

不接触网络即可复核：用 json.load 按索引读取 Charles；header 名转小写，
按 `:authority > host > flow.host` 取主机；调用 `farm.fullsign.decode_a5`、
`mtgsig.a9_codec.decode`、B 固定 AES-CBC 解码与 `mtgsig.scfg.decode_scfg_data`；
对响应 DFP/XID 和后续签名做字符串相等比较，只报告布尔值和索引。
原始包及私有 profile 均未修改。

## 登录后大体积 bio 的 a2 例外（有限离线诊断）

全量 audit 的完整 a2 对拍为 **92/93**。唯一不一致是登录后的 #766 app bio；
它的业务响应为 code0，但这不能反推服务端是否实际校验了 a2。
本次没有调整密码常量，没有从期望 a2 反算签名序号，没有改变产品实现。

| 索引 | 请求正文 UTF-8 字节数 | 整体 a2 匹配 | 使用捕获前半与独立 a5.b2 重算全部后半匹配 |
|---|---:|---|---|
| 184 | 678 | true | true |
| 599 | 677 | true | true |
| 766 | 49436 | false | true |

#766 核验结果：

- body 是 ASCII JSON，无 NUL；字符数、UTF-8 长度、Content-Length 与抓包 body size 全部相同。
- method 与 HTTP 请求首行相同；重建 path/query 与首行完全相同，没有 `%` 编码差异。
- 去掉 a2 后的紧凑 mtgsig JSON 与抓包原 header 去掉末尾 a2 的字节表达相同。
- a10 与两个较小 bio 相同；从 a5 解出的 b2 合法且递增。
  #766 的 b2 与 b17/b18 均不相等，故不能用后两项替代 b2；下面的 pass2 校验仍使用 b2。
- 用 **捕获 a2 前 8 字节 + 解密 a5.b2**，能够复算其全部后 8 字节；
  本例的差异在消息/HMAC/pass1 一侧，不能归因于已验证的 pass2 序号公式。

保持 URL、mtgsig payload、配置及独立序号不变，只修改正文做了两项有限检查：

| 正文候选 | 候选字节数 | a2 匹配 |
|---|---:|---|
| 原始正文 | 49436 | false |
| 空正文（检查签名时正文缺失的假设） | 0 | false |
| 仅将 JSON `\/` 还原为 `/` | 48654 | false |

该请求的紧凑 JSON 重序列化等于第三项，不重复测试。源码和已有证据未提供签名正文的
截断阈值，因此没有尝试任意长度或遍历所有前缀。
旧 `从app初次打开到登录被拦截.chlsj` 的 #777（50688 字节）复核得到同样形态：
整体 a2 不匹配、独立完整 pass2 匹配。两个大体积样本与长度有关联，
但尚不足以证明长度就是原因。**根因仍未知**，不能声称该大正文边界已经完整复现。
