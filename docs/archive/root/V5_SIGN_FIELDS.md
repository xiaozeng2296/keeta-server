# /v5/sign 完整传输字段表（合并版·逐字段无省略）

> 历史研究资料，来源 `codex/keeta-project@6197c528`；保留当时的观测与未完成项，不代表新项目当前状态。当前规则见 [字段状态](../../MTGSIG_FIELDS_STATUS.md)，复跑入口及已修正结论见 [离线研究指南](../../research/OFFLINE_RESEARCH.md)。文中的旧 `dump/`、抓包及设备路径仅作证据索引，原材料未随仓库发布。

> 2026-10-02 原生更正：b16 三组是 SDK 上报次数与相对时点，b17 为 POST 签名前置计数，b18 在 SDK userID=nil 时递增。旧传感器/计数关系猜测以 [新原生证据](../../research/B_COUNTERS_RENDER_20261002.md) 为准。

> 2026-09-28 密码与状态更正：a7/a8 的本地生成见 [LOCAL_ID_RESEARCH](../LOCAL_ID_RESEARCH.md)；
> a9 三种模式及派生见 [A9_PROVIDER_NOTES](../A9_PROVIDER_NOTES.md)；完整 envelope 见
> `docs/ENVELOPE_SDK.md`；逐字段变换的固定表和例外见 [CORPSE_CODEC](../CORPSE_CODEC.md)。
> 下文 SHA224、未知 a7、固定单一 Feistel 与启发式 Caesar 等旧断言不能作为当前实现依据。

> 目标接口:`pikachu.mykeeta.com/v5/sign`(SDK 注册链路 step 100),返回 `dfp`(=a8=m27)+ `clientIp`(代理出口)。
> 本文合并 `FINGERPRINT.md §一/§二`(签名 + a5/a9)与 `DEVICE_FINGERPRINT_FIELDS.md §13`(corpse body),
> 统一成 /v5/sign 一处可查。样本:iPhone 11(iPhone12,1 / iOS 16.1.1),设备 a1=`6fa25bc1-…-b009c3b3092a`。
> 明文来源:frida hook libz deflate 抓压缩前 + 离线解密,存 `dump/collect_plain/` 与 `/tmp/keeta_sig/decoded_clean.json`。

> **★★ 2026-09-27 实测更新(以此为准,推翻下文多处"dfp 不变/恒定"表述)**:当前 chaos(9 条数据卷根路径 crtime spoof + 单调递增)下,**每次 chaos new 都下发不同的新 dfp**,不再恒定 `aee320`。故下文 m157/m251 等字段"spoof 后 dfp 仍 aee320""dfp 不变"的判语**已过时**。
> ⏳ **机制未核实**:尚未抓包核对 m251 上传的 crtime 值是否真的变了,因此**不能断定就是 crtime(m251)驱动 dfp 变化**——也可能是整体信号覆盖变全。核对前保留 m251 字段的"per-device 真值"描述,但换机结论以本横幅为准。

> **a7/a8 阶段语义（以实包为准）**：首次注册请求里的 a7/a8 可能是本地
> 候选值。`/fingerprint/v1/info/report` 响应 `data.result` 后，后续 a7
> 才是落盘 xid；`/v5/sign` 响应 `data.dfp` 后，后续 a8 才是服务端 dfp。
> 具体前后值和索引见 `REGISTRATION_ID_STAGES.md`。

---

## 0. 传输结构总览(3 指纹面 + 1 签名)

| 面 | 位置 | 内容 | 加密 | 明文产物 |
|----|------|------|------|---------|
| **① mtgsig 头** | HTTP header `mtgsig` | a0–a10 + x0(签名 + 静态指纹 + 两加密子通道) | JSON 明文 | 直接可读 |
| **② a5 子通道** | mtgsig 内 `a5` | 风控采集主数据 b1–b25 | `base64(RC4变体(zlib(JSON)))`,key=`(a1+a3+a4)ASCII ^ k2buf` | 已解密 |
| **③ a9 子通道** | mtgsig 内 `a9` | SIUA 设备指纹数组 `0/1/2/3` | `hex(crc32)+base64(CBC(Feistel(zlib(JSON))))`,密文体 512B=32×16 | `dump/collect_plain/a9_plain.json` |
| **④ Body corpse** | 请求体 | 127 字段设备画像 | 逐字段 Caesar(`obf=((plain-33+K)%94)+33`)+ deflate | `/tmp/keeta_sig/decoded_clean.json` |

**签名 a2** 只绑 `method + path + body + a1 + a4`,服务端只校验 `a2[0:8]`(离线可复现)。
三个指纹面(corpse / a5 / a9)交叉冗余上报**同一台机**,服务端比对一致性 + 历史聚类 → 下发 dfp。

---

## ① mtgsig 头 a0–a10 + x0（签名 + 静态指纹）

| 字段 | 语义 | 实测值 | 性质 / 依据 |
|------|------|--------|------------|
| **a0** | 协议版本 | `2.5`(国内 3.0) | 常量 |
| **a1** | 设备/安装 UUID(内部当 app-key `ak`;**密钥派生种子**) | `6fa25bc1-3aca-4845-a719-b009c3b3092a` | 每请求明文携带,每设备唯一;派生 K/k2buf/a5 密钥(`k2buf.go`) |
| **a2** | **请求签名** | `de58fb0b…`(32hex) | HMAC-SHA1→9 轮 a2Mix→替换→pass1/2;**服务端只校验 a2[0:8]**,绑 method+path+body |
| **a3** | 端/平台标识 | `20`(本次实包;FINGERPRINT.md 旧样本记 25→**值随版本/上下文变,非恒定**) | 疑端/SDK/版本 |
| **a4** | 时间戳(秒) | `1790130971` | 每请求 |
| **a5** | 采集 blob(见②) | 432B | `base64(RC4变体(zlib(采集JSON)))` |
| **a6** | 标志位 | `0` | 常量 |
| **a7** | 未定 | 108B | 待反 |
| **a8** | **客户端缓存 dfpID**(≠响应 dfp!) | 本次实包 `dad7b0fdfbd3a2dbf73f84f6b86a42963a4f2c2f48f52177ef5435b5`(SHA224 28B,**dad7 前缀=localid 家族,chaos 后新生成**) | ★见下"服务端重识别铁证":请求 a8=客户端本地缓存(轮换),**响应 dfp=服务端重识别值(aee320,不变)**,两者可不等;a8 由 `SAKGuardDeviceFingerprint._static_dfpID`(outidinfo 缓存)提供 |
| **a9** | 加密设备指纹(见③) | 776B | `crc32+base64(CBC(Feistel(zlib(JSON))))`,启动算一次缓存 |
| **a10** | 签名计数器 | `"3,N"`,N 每签递增 | 递增 |
| **x0** | 未定 | `2` | 常量 |

### a2 签名用的明文（"什么被签"）

```
签名输入 = HTTP method + path + body(corpse) + a1(deviceId) + a4(ts)
HMAC key = 由 a1 派生 (k2buf = salt ⊕ a1)
校验     = 服务端只比对 a2[0:8] (前 8 hex),绑 method+path+body
```
> 拿到 a1 + method/path/body + ts 即可算 a2 → 离线签已纯复现,code=0(memory keeta-offline-signing)。
> a2 内部:a2=HMAC→9 轮 a2Mix(T 表网络)→pass1/2;a5 密钥=RC4 变体;K2buf=salt⊕a1;a9=Feistel/CBC(国内 Go 已逐位复现)。

---

## ② a5 采集明文（风控采集主数据）

### 顶层 b* 字段

| 键 | 语义 | keeta 实测 | 校验? / 依据 |
|----|------|-----------|-------------|
| b1 | 设备指纹主体(嵌套 JSON,见下) | (见下) | — |
| b2 | 签名序号,每次签名 +1 | 19 | ❌ 服务端不校验(纯拟真,`oracle.go`) |
| **b3** | a5 采集序号,递增 | 1 | ✅ **服务端校验,改即 403**(`oracle.go`) |
| b4 | bundleId 包名 | `com.sankuai.sailor.ifooddelivery` | 自证 |
| b5 | app 版本串 | `3.12.401` | 自证·交叉 m144 |
| b6 | app 版本号(int,=b5 去点) | `312401` | 自证 |
| b7 | app 启动/安装时间戳(秒) | 1790040379 | 自证(Unix 秒) |
| b8 | 当前时间戳(秒),a4≈b8+offset | 1790040379 | `oracle.go` |
| b9 | 时间戳(秒)(=b8) | =b8 | 自证 |
| b10 | SIUA/SAKGuard SDK 版本 | `5.21.10` | 自证·交叉 m152 |
| b11 | SDK 版本(同 b10) | `5.21.10` | 自证 |
| b12 | 端/平台标志(恒 2) | `2` | 疑 iOS 端类型 |
| b13 | 计数(疑已采子项数) | `2` | 待反 |
| b16 | **SDK 上报记录**：三组次数/最近调用相对秒/最近 HTTP200 回调相对秒 | `[0,0,0],[1,0,0],[0,0,0],1` | 已定位原生请求写入、回调与序列化；见 2026-10-02 报告 |
| b17 | 计数 | 18 | 待反 |
| b18 | 计数(疑签名序号镜像) | 0 | 待反 |
| b20 | 计数 | —(国内 50) | 待反 |
| b21 | 时间戳(秒) | —(国内 1787562278) | `oracle.go` |
| b22 | **运营商 MCC/MNC**(国家:网络) | `[{"BR":"867"}]`(巴西) | 自证 |
| b23 | 设备标识串(base62,14 字符) | —(国内 `OLLpgcNz0O896E`) | 自证,语义待反 |
| b24 | 设备标识串(base62,36 字符) | —(国内 `daVFbMhHFtbhr2hNK9kDLtzQvg5K0ZZz6W3h`) | 自证,语义待反 |
| b25 | 标志位 | —(国内 0) | 标志 |

### b1 内层（设备指纹主体）

| 键 | 实测 | 含义 | 证据 |
|----|------|------|------|
| b1.1–14 | 本样本多空 `""` | 分项设备属性槽(按位填充,本 boot 未填,但槽位存在=SDK 预留采集面) | — |
| b1.33 | 见下 | **环境/风控检测子对象** | 见 b1.33 |
| b1.44 | 空 | 预留槽 | — |
| b1.55 | keeta `1055422178`(国内 3010776750) | 数值指纹(每设备不同) | per-device,待反 |
| b1.56 | `0` | 标志 | 标志 |
| b1.57 | `1894370865`(**两设备一致**) | 固定值/编译期常量(非设备相关,红鲱鱼) | 自证(跨设备恒定) |
| b1.58 | `1790040379912` | 毫秒时间戳 | 自证(Unix ms) |
| b1.100 | `1.1.10`(国内样本) | 子模块版本 | 自证 |

### b1.33 环境检测项（风控核心:反越狱/反代理/反调试,17 槽 + schema）

三样本(keeta / 国内 / corpse m294)**逐字节相同**,大量空或 `-`:

| 键 | 值(三样本一致) | 说明 |
|----|---------------|------|
| [0] | `23` | 检测 schema 版本/项数(恒 23) |
| [1] | `""` | 检测结果槽(空) |
| [2] | `""` | 检测结果槽(空) |
| [3] | `-` | 检测结果槽(未命中占位 `-`) |
| [4] | `-` | 检测结果槽(`-`) |
| [5] | `""` | 检测结果槽(空) |
| [6] | `""` | 检测结果槽(空) |
| [7] | `-` | 检测结果槽(`-`) |
| [8] | `-` | 检测结果槽(`-`) |
| [9] | `-` | 检测结果槽(`-`) |
| [10] | `-` | 检测结果槽(`-`) |
| [11] | `1\|2` | 枚举(恒 `1\|2`) |
| [12]–[16] | `""` | 检测结果槽(空) |

> 采集面(17 槽 + schema 23)清楚,但每槽对应哪项检测(越狱/代理/调试/注入)明文看不出,不臆测顺序。
> 真机检测结果为空 ⇒ 走 a9 加密通道或另有开关,须反编译 SAKGuard `b1.33` 填充函数钉死。

---

## ③ a9 加密明文（SIUA 设备指纹数组,`dump/collect_plain/a9_plain.json`）

结构 = `{"0":schema, "1":[基础16项], "2":[扩展23项], "3":采集来源map}`。逐项对应 corpse m 字段:

### a9["0"]
| 值 | 含义 |
|----|------|
| `12` | schema 版本/项数 |

### a9["1"]（基础 16 项,顺序固定）
| # | 实测值 | 含义 | =corpse |
|---|--------|------|---------|
| 1 | `0` | 标志 | — |
| 2 | `WiFi` | 网络类型 | m162 |
| 3 | `0.000000` | 浮点占位 | m15/m161 |
| 4 | `[5,100]` | 常量数组 | m138 |
| 5 | `Darwin` | 系统名 | m147 |
| 6 | `Apple` | 厂商 | m250 |
| 7 | `中国电信` | 运营商名 | m9 |
| 8 | `iOS16.1.1` | iOS 版本串 | m160 |
| 9 | `N104AP` | 主板型号 | m158 |
| 10 | `zh-Hans-CN` | 语言 | m164 |
| 11 | `iphone` | 设备类小写 | m249 |
| 12 | `iPhone` | 设备类 | m151 |
| 13 | `Asia/Shanghai (GMT+8) offset 28800` | 时区 | m165 |
| 14 | `828*1792` | 屏幕分辨率 | m167 |
| 15 | `22.1.0` | 内核大版本 | m14 |
| 16 | `-` | 占位 | — |

### a9["2"]（扩展 23 项,顺序固定）
| # | 实测值 | 含义 | =corpse |
|---|--------|------|---------|
| 1 | `0` | 标志 | — |
| 2 | `1790055550727.318` | 系统启动绝对时间(ms) | m148 |
| 3 | `127933894656` | 磁盘总量 | m132 |
| 4 | `{"33":{"0":0,"1..16":"-","44":""}}` | **环境检测对象**(同 b1.33/m294) | m294 |
| 5 | `0.500000` | 电池电量 | m142 |
| 6 | `15` | 亮度/电池 | m143 |
| 7 | `com.sankuai.sailor.ifooddelivery` | BundleID | m154 |
| 8 | `3.12.401` | SDK 版本 | m144 |
| 9 | `21222420480` | 可用磁盘(实时) | m131 |
| 10 | `1790074723963` | 当前墙钟(ms) | m150 |
| 11 | `0000000000000BD1877A2D34B494FBC0662FF65F8C452A179003492613172228` | 设备指纹 hash/csecuuid(64hex) | m153 |
| 12 | `4038852608` | **hw.memsize 精确物理内存**(真硬件熵) | m157 |
| 13 | `[]` | 空数组 | m253 |
| 14 | `0` | 标志 | m254 |
| 15 | `0` | 标志 | m255 |
| 16 | `0` | 标志 | m256 |
| 17 | `9B382CCD5C69456FA5345F047C259D2801` | 34hex 会话 nonce(每会话变,非持久) | a9 自带 |
| 18 | `unknown` | 占位 | m126/m133 |
| 19 | `iPhone12,1` | 机型 | m166 |
| 20 | `-` | 占位 | — |
| 21 | `Alpha` | 渠道 | m125 |
| 22 | `1787189782779.004` | 内核 boottime | m149 |
| 23 | `1790055284736` | 进程启动时间戳 | m155 |

### a9["3"]
| 值 | 含义 |
|----|------|
| `{"253":5,"127":5}` | 采集来源/耗时码映射(哪些字段来自哪个源) |

---

## ④ Body corpse 127 字段（设备画像主体,全表逐字段）

证据等级:GT=hook 抓到明文/自证值(最硬)｜TR=底层读取 trace 实锤到源｜ST=解码后结构可辨｜?=值太短/未匹配 K 未解。
状态列 = chaos-new(chaos + spoof)前后 diff 判定。

| 字段 | 含义 | 证据 | 设备A值 | chaos-new 状态 |
|------|------|------|---------|----------------|
| m1/m2 | 固定标志0 | GT | 0 | ⬜常量 |
| m3 | 产品名 | GT | Keeta | ⬜常量 |
| m4 | 空占位 | GT | — | ⬜常量 |
| m5 | 设备名 | GT | Uisz's iPhone | ✅新机已变 |
| m6 | 可用内存(实时) | GT | 120619008 | ✅自然变 |
| m7 | SDK协议版本 | GT | 1.0 | ⬜常量 |
| m8 | SIM MCC/MNC数组 | GT | [{mcc460,mnc11}] | ✅SIM可空 |
| m9 | 运营商名 | GT | 中国电信 | ✅SIM可空 |
| m10 | SIM相关0 | GT | 0 | ✅SIM可空 |
| m11 | IDFV | GT | B00AC324… | ✅新机已变 |
| m12 | IDFA | GT | 1647261C… | ✅已置换 |
| m13 | 固定0 | GT | 0 | ⬜常量 |
| m14 | 内核大版本 | GT | 22.1.0 | 🟡OS版本级 |
| m15 | 浮点0 | GT | 0 | ⬜常量 |
| m16 | 充电/低电标志 | GT | 1 | 🟡实时状态 |
| m17 | 固定1 | GT | 1 | ⬜常量 |
| m18/m19 | 固定0 | GT | 0 | ⬜常量 |
| m27 | dfp(服务端回填,非输入;=a8) | GT | d3ec07… | —回填 |
| m30 | 固定3 | ST | 3 | ⬜常量 |
| m122 | base64 AA== | GT | AA== | ⬜常量 |
| m123 | 空占位 | GT | — | ⬜常量 |
| m125 | 渠道 | GT | Alpha | ⬜常量 |
| m126 | unknown占位 | GT | unknown | ⬜常量 |
| m127 | 环境/型号串 | GT | unknown | 🟡低价值 |
| m128 | 越狱/环境检测blob | ST | (空/有值) | 🟡状态非身份 |
| m129 | **magic 字段=SDK magicNumber 魔数**(默认0x19830119) | TR(IDA) | 428015897 | ⬜SDK常量(注⑧) |
| m130 | SIM的MCC+MNC | GT | 46011 | ✅SIM可空 |
| m131 | 可用磁盘(实时) | GT | 21289689088 | ✅自然变 |
| m132 | 磁盘总量 | GT | 127933894656 | ⬜机型级 |
| m133/m134 | unknown | GT | unknown | ⬜常量 |
| m135 | 磁盘剩余%/温度 | GT | 29.85 | ✅自然变 |
| m136 | 空 | GT | — | ⬜常量 |
| m137 | 完整内核version串 | GT | Darwin…22.1.0 | 🟡OS版本级 |
| m138 | 常量 `[5,100]`（运行时构造，无静态字面量） | GT | [5,100] | ⬜常量(运行时) |
| m139 | CPU核数 | GT | 6 | ⬜机型级 |
| m140 | CPU架构 | GT | arm64e | ⬜机型级 |
| m141 | 固定0 | GT | 0 | ⬜常量 |
| m142 | 电池电量 | GT | 0.50 | 🟡实时状态 |
| m143 | 电池/亮度 | GT | 15 | 🟡实时状态 |
| m144 | SDK版本 | GT | 3.12.401 | ⬜常量 |
| m145 | 安装来源 | GT | appstore | ⬜常量 |
| m146 | 固定0 | GT | 0 | ⬜常量 |
| m147 | 系统名 | GT | Darwin | ⬜常量 |
| m148 | 系统启动绝对时间戳 | GT | 1790055550727 | ✅新机已变 |
| m149 | 内核boottime | GT | 1787189782779 | ✅新机已变 |
| m150 | 当前墙钟(ms) | GT | 1790062508661 | ✅自然变 |
| m151 | 设备类 | GT | iPhone | ⬜机型级 |
| m152 | App版本 | GT | 5.21.10 | ⬜常量 |
| m153 | 设备指纹hash(64hex,csecuuid) | GT | 000…BD1877A2D34… | ✅新机已变 |
| m154 | BundleID | GT | com.sankuai.sailor… | ⬜常量 |
| m155 | 进程启动时间戳 | GT | 1790055284736 | ✅新机已变 |
| m156 | IPv6地址 | GT | 240e:467:1b72… | 🟡网络级 |
| **m157** | **★hw.memsize 精确物理内存** | TR | 4038852608 | ❌真硬件熵(注①) |
| m158 | 主板型号 | GT | N104AP | ⬜机型级 |
| m159 | 主机名 | GT | Uiszs-iPhone | ✅新机已变 |
| m160 | iOS版本串 | GT | iOS16.1.1 | 🟡OS版本级 |
| m161 | 浮点0 | GT | 0 | ⬜常量 |
| m162 | 网络类型 | GT | WiFi | ⬜易变 |
| m163 | 固定0 | GT | 0 | ⬜常量 |
| m164 | 语言 | GT | zh-Hans-CN | ⬜常量 |
| m165 | 时区 | GT | Asia/Shanghai | ⬜常量 |
| m166 | 机型 | GT | iPhone12,1 | ⬜机型级 |
| m167 | 屏幕分辨率 | GT | 828*1792 | ⬜机型级 |
| m175 | 368B AES会话blob | GT | 8B10D32A… | ✅每启动变 |
| **m200** | **OS编译/封存日期时间戳** | GT | 1667453465 | 🟡OS版本级(未改,注②) |
| m218 | 占位串 | ST(K=88) | `unknown` | ⬜占位(m307源码7) |
| m219 | 占位串 | ST(K=69) | `unknown` | ⬜占位 |
| m220 | 空 | ST | `` | ⬜空 |
| m221–m236 | 短串/空(多数未解,A==B) | ? | ohehiqh等 | ⬜常量/未解 |
| m223 | 外接配件枚举(EAAccessoryManager) | ST(K=6) | `{"nameAttachedAccessories":"","AccessoriesAttached":"0","numberAttachedAccessories":"0"}` | ⬜0个配件,机型无关 |
| m237 | ASLR/vm_region(每启动) | ST | {vm_region…} | ✅每启动变 |
| m238 | dyld槽位(每启动) | ST | {systemVersion…} | ✅新机已变 |
| m239 | m251 文件 birthtime 按原顺序以 `%ld%ld` 拼接的 MD5 | ST | 32hex | 已由 collector 和 5 份样本验证，见 docs/M239_SOURCE.md |
| m249 | iphone | GT | iphone | ⬜常量 |
| m250 | 厂商 | GT | Apple | ⬜常量 |
| m251 | **文件系统crtime+inode**(数据卷恢复时刻) | ST | {tm,st,si,f://private/var} | ✅chaos的APFS时间已覆盖(注③) |
| m253 | 空数组 | GT | [] | ⬜常量 |
| m254–m256 | 固定0 | GT | 0 | ⬜常量 |
| m259/m260 | 标志(单字符) | ST | `0` | ⬜标志(K不可唯一锁) |
| m268/m269 | 空 | ? | — | ⬜常量 |
| m270 | 容器Bundle路径UUID | ST | /private/var/Containers/Bundle… | ✅每装变 |
| m271 | 容器Data路径UUID | ST | /private/var/Containers/Data… | ✅每装变 |
| m272 | 标志 | ST | `0` | 🟡标志 |
| m273/m275 | 空 | ? | — | ⬜常量 |
| m274 | 固定1 | GT | 1 | ⬜常量 |
| m293 | localid SHA224(钥匙串) | GT | dad741e2… | ✅随chaos变 |
| m294 | 事件/权限状态map(=b1.33环境检测) | GT | {…} | —内部 |
| m303 | 空 | GT | — | ⬜常量 |
| m304 | 美团派发数字ID(账号/install级) | GT | 10000057339063 | 🟡账号级,非设备锚(注④) |
| m305 | 屏幕分辨率 | GT | 828*1792 | ⬜机型级 |
| m306 | dfp缓存blob(54子字段) | ST(K=16) | bundle→dfp(aee320)映射/磁盘卷证书/TKW39C3422/越狱hook检测/Mach-O头/框架清单/模块基址表 | —内部缓存 |
| m307 | 内部:空字段元信息 | GT | {m4:5,…} | —内部 |
| m311 | **App 构建时间**(Keeta.app/Info.plist birthtime,fstat) | GT+双机SSH(K=40) | `1789756165`(2026-09-18,**两机相同**) | 🟦版本常量,非设备锚(注⑦) |
| m321 | 2位数字 | ST | `02` | ⬜低值 |
| m312 | 计数(小int) | ST(K=49) | `593` | 🟡计数,非身份 |
| m313 | 固定2 | GT | 2 | ⬜常量 |
| m314 | MD5("TKW39C3422")=MD5(TeamID) | TR | EA6BFC6F… | ⬜app常量(注⑤) |
| m315 | 固定0 | GT | 0 | ✅每启动变 |
| m318/m319/m329 | 单字符 | ? | @/Q/M | ⬜常量 |
| m320 | session随机数 | GT | 774506003 | ✅每启动变 |
| m324 | session token | GT | 7A692C51… | ✅每启动变 |
| m325 | 代码完整性 | ST(K=92) | {version:1, c_funcs:[6], oc_funcs:[14]}(函数序言ARM64指令hex) | 🟡代码级非身份 |
| m328 | TLS证书pin(cert SHA→CN 映射) | ST(K=23) | `{"<base64 cert SHA>":"/CN=*.mykeeta.com…"}` | 🟡证书级非身份 |
| m332 | ★WebRTC ICE srflx candidate(泄漏真实公网IP) | ST(K=24) | `candidate:… 120.35.98.81 typ srflx`(=响应clientIp) | 🟧网络锚,每次变但泄真公网IP(注⑨) |
| m333 | 未解小token(共享缓存slide假锚) | ? | N8PNVWNNNN | ✅重启即变(注⑥) |

### corpse 注释

- **注①(m157)**:trace 实锤 `sysctlbyname("hw.memsize")`,A=4038852608/B=4038836224 差 4 页。真硬件熵,chaos 不改精确内存。**已实测 spoof 后 dfp 仍 aee320 → 非 dfp 决定项**。
- **注②(m200)**:内核编译/OS 封存时间戳(落在内核冻结与公开发布之间,流水线自洽)。**OS 版本级**——同 build 所有 iPhone 相同,非设备锚;改成假值反而露馅。m14/m137/m160 同理。
- **注③(m251)**:数据卷 crtime,纳秒唯一=真实恢复时刻。~~旧结论:chaos 只改 stat 层、getattrlist 读真值、dfp 不变~~ → **2026-09-27 推翻:当前 chaos 9 路径 crtime spoof 后每次 new 都换新 dfp**(见顶部横幅)。⏳ m251 上传值是否随之变更**未抓包核对**,机制待定。
- **注④(m304)**:14 位十进制(**非 MD5、非常量**——勿与 m129/m314 混淆)。audit 工具归类 `ACCOUNT={'m304'}`=账号级;匿名态为服务端派发 install ID。存活→走 outidinfo 回填(已知机制);清掉→可轮换。**账号级天然非设备硬件锚**。
- **注⑤(m314)**:hook CC_MD5 溯源=MD5("TKW39C3422")=MD5(Apple TeamID),app 常量非设备锚。
- **注⑥(m333)**:dyld 共享缓存 slide,**重启即变**,非硬件锚。
- **注⑦(m311)★来源钉死+跨机纠正(2026-09-27 frida+双机SSH 实证)**:`1789756165`=2026-09-18 18:29:25 UTC = **`Keeta.app/Info.plist` 的 birthtime**。App 用 `fstat` 读该 plist st_birthtime(偏移 80)填 m311(frida hook fstat 命中;SSH `stat -c %W` 定位到 Info.plist)。
  **★双机对比结论:m311 = App 构建/打包时间,不是设备锚**。实测两台不同物理机(${KEETA_SSH_PASSWORD} Uisz 16.1.1 / ${KEETA_SSH_PASSWORD} Dloik 16.2)Info.plist birthtime **完全相同 = 1789756165(同一秒)**⇒ 不是 per-device 安装时刻,而是**该 Keeta 版本的构建/打包时间戳,baked 进 Info.plist**,install + chaos APFS clone 都保留原值。**版本级常量(同 m200 OS 封存戳一类),所有装此版本的设备都一样,不区分设备**。⇒ 原"per-install chaos-surviving 设备锚"判断**作废**——它确实 chaos 洗不掉,但因为是版本常量,对设备识别无贡献。
- **注⑧(m129)IDA 逆向钉死**:= corpse `magic` 字段 = SAKGuard SDK `magicNumber` 属性,`0x19830119`(=428015897)是硬编码默认值(property nil 兜底)。加载于 `-[SAKWindFingerprintGenerator y64bGjEh]`(写 "magic" 键)与 `sub_10033DAB0`。0x19830119≈1983-01-19 开发者哨兵魔数,app/SDK 身份标识,**非设备特征、非密码学**——两机相同的根因。同函数兄弟键=finger_version/utm_medium/ch/dpid/business/brand 等平台语义。
- **注⑨(m332)★WebRTC 公网 IP 泄漏**:K=24,空格替身还原后 = 标准 WebRTC ICE candidate(STUN srflx):`candidate:2 1 UDP 1686109951 120.35.98.81 4693 typ srflx raddr 0.0.0.0 rport 0`。srflx 地址 `120.35.98.81` **= /v5/sign 响应的 clientIp**,即真实公网出口 IP。**WebRTC/STUN 绕过 HTTP 代理直连 STUN 服务器拿公网映射 → 即使 App 走 Charles/代理,m332 仍泄漏真实公网 IP**(v4+v6 都有)。每次采集变(端口/candidate 号),但暴露的公网 IP 是真网络锚。

---

## 5. 真锚分级表（重识别贡献度 × 持久性 × 撬动性）

> 分级 = **熵(能否区分两台同型号真机)× 持久性(扛不扛 chaos new)× 实测撬动性(spoof 后 dfp 变不变)**。
> 核心前提:逐字段实测下来**没有任何单一字段是「改了就能换 dfp」的硬锚**——分级衡量的是对服务端**重识别的贡献度**,不是找那个不存在的单点。

### 🟥 S 级 — 真硬件熵（per-device 真值,chaos 改不到,但实测撬不动 dfp）
| 字段 | 含义 | 熵来源 | 实测 |
|------|------|--------|------|
| **m157** | `hw.memsize` 精确物理内存(A/B 差 4 页) | 芯片级真值,chaos 不改 | spoof 后 dfp 仍 aee320 |
| **m251** | 数据卷 crtime + inode(`//private/var`) | APFS 落盘恢复时刻,纳秒唯一 | **2026-09-27:chaos 9 路径 crtime spoof 后每次 new 换新 dfp**(旧"dfp 不变"作废);m251 上传值是否变更⏳未核对;**双机 m157 各异证其为真per-device** |

> **★双机验真(2026-09-27,两台手机同法对比)**:m157(hw.memsize)两机不同(4038852608 vs 4038836224)= 真 per-device 硬件熵✓;m251 真值走 getattrlist(deep crtime,chaos 只改 stat 层)= 真 per-device✓。**m311 两机完全相同 → 是 App 构建时间版本常量,已移出 S 级(见 C 级 + 注⑦)**——这条对比正是"两机相同=常量,但要知道为什么"的落点:m311 填的是 Info.plist 里 baked 的构建戳。

### 🟧 A 级 — 强持久弱信号（链下重识别,非 corpse 单点）
| 信号 | 载体 | 持久性 | 定性 |
|------|------|--------|------|
| **Incognia installationId** | 独立 SDK,钥匙串 + `events/v3` 位置/行为图谱 | 跨重启稳定,chaos new 轮换 | 靠服务端位置轨迹重识别 |
| **outidinfo dfp 缓存** | `com.sakguard.outidinfo` 钥匙串 | chaos 清掉→服务端立刻回填同一 dfp | 服务端重识别铁证,持久性在服务端 |
| **m304** | 美团派发 14 位数字 ID(账号/install 级) | per-device 稳定,chaos 存活未实测 | 账号级,存活则走 outidinfo 回填,非新锚 |
| **m332** | WebRTC ICE srflx 真实公网 IP(v4+v6) | STUN 直连绕 HTTP 代理 | ★即使走 Charles/代理仍泄真公网 IP,喂服务端 IP 历史图谱(注⑨) |
| ~~App Attest~~ | Incognia SE 密钥 | 清钥匙串即 regenerate | **已降级**:仅「真机非农场」布尔,不携带跨机身份 |

### 🟨 B 级 — 机型级聚类信号（所有 iPhone 11 相同,喂模糊匹配骨架）
`m166`(机型) `m158`(主板) `m132`(磁盘128G) `m167/m305`(分辨率) `m139/m140`(6核/arm64e) `m151`(iPhone) `m250`(Apple) `m130/m9`(运营商) + RegionInfo CH/A

### 🟦 C 级 — OS/App 版本级（同 build 所有机相同,不区分设备）
`m14`(内核大版本) `m137`(完整内核串) `m160`(iOS版本) `m149`(boottime) `m200`(OS编译/封存戳,别乱改) **`m311`**(App构建戳=Info.plist birthtime,双机相同,注⑦)

### 🟩 D 级 — 会话随机（每启动变,零重识别价值）
`m175`(AES会话blob) `m237`(vm_region/ASLR) `m320`(session随机数) `m324`(session token) `m333`(共享缓存slide假锚,重启即变) `m312/m332`(每启动小串) `a9[2][17]`(34hex会话nonce)

### ⬜ E 级 — app 常量红鲱鱼（所有安装/所有机相同,反复被误判成锚）
`m129`=428015897 `m314`=MD5(TeamID) `m144`(SDK版本) `a1`=6fa25bc1 `a5 b1.57`=1894370865 `m152`(App版本)

### ♻️ 可轮换 — 已被 chaos/清钥匙串处理（本机身份 ID,已全绿）
`m11/m12`(IDFV/IDFA) `m153`(csecuuid) `m293`(localid) `m5/m159`(设备名/主机名) `m270/m271`(容器路径UUID)。`m239` 另与 `m251` 文件 birthtime 明细绑定，不由 localid 派生，见 [M239_SOURCE](../M239_SOURCE.md)。

### 分级两条铁律
1. **物理层已封死**:序列号/ECID/UDID/MAC 沙盒全返 `None`(live 实证)→「偷传唯一硬件 ID」通道不存在。
2. **真锚是分布式的**:dfp 恒定 = 服务端两套系统(SAKGuard ~100 弱信号融合 + Incognia 位置/行为图谱)对 S级熵 + B级机型组合 + IP历史 + 首见留痕的**概率重识别**;逐字段 spoof 都无效。

---

## 6. 结论对齐

- **签名 a2** 只绑 method/path/body + a1 + ts,离线可复现(code=0)。
- **三个指纹面**(corpse 127 / a5 b1-b25 / a9 SIUA 数组)交叉冗余上报同一台机;真硬件熵仅 **m157(memsize)+ m251(crtime)**,二者 spoof 后 dfp 均不变。
- **dfp 恒定** = 服务端 ~100 弱信号模糊融合(概率重识别)+ 首见历史,**无单一可撬字段**;要换 dfp 只能真换物理机,或整体改全 fingerprint + 换网络。
- **★服务端重识别 wire 级铁证(2026-09-27 `新机之后尝试登录.chlsj` 实包)**:chaos new 后 /v5/sign 请求头 **a8=`dad7b0fd…`(客户端刚轮换的本地 dfpID)**,但**响应 `dfp=aee320…`(老锚,不变)**。⇒ 服务端**无视客户端上报的轮换 a8,直接返回重识别出的 aee320**,再次证明 dfp 持久性在服务端不在客户端。a1=`6fa25bc1…` 亦穿 chaos 不变(SAKGuard 持久 deviceId)。
- 详见 memory `keeta-devicecheck-anchor` / `keeta-m251-fs-crtime-anchor` / `keeta-offline-signing`,及 `FINGERPRINT.md`(a9/v73 表)、`DEVICE_FINGERPRINT_FIELDS.md`(锚分级实验)。

---

## 7. 字段来源与填充原因（provenance：为什么填这个值）

> 回答「值哪来的 / 为什么两机相同就是常量」。分四类来源,**m307 是 SDK 自带的采集来源码映射**,是最硬的 provenance 证据。

### 7.1 ★ m307 采集来源码（SDK 自证每字段哪来的）

m307 = `{"m4":5,"m9":5,"m12":2,"m18":7,"m126":7,"m127":5,"m133":5,"m134":5,"m136":7,"m161":7,"m253":5,"m256":7,"m303":7}`
逐字段值对照后,来源码语义(实测归纳):

| 来源码 | 语义 | 覆盖字段 | 实测值 |
|--------|------|---------|--------|
| **0** | 未采集/无源(空) | m123,m128 | 全空 `""` |
| **5** | SDK 默认占位(该项不适用本设备/系统→填常量) | m4,m127,m133,m134,m253 | `""`/`unknown`/`[]` |
| **7** | 采集返回空→填零默认 | m18,m126,m136,m161,m256,m303 | `0`/`0.000000`/`""` |
| **2** | 真实读取(有值) | m12(IDFA) | 实际 UUID |

⇒ **文档里标"空/unknown/常量"的一大批字段,不是我们设备采集失败,而是 SDK 按来源码 5/7/0 填的默认占位**——这类字段在任何设备上都一样,`两机相同=常量`的根因在此,不是设备特征。

### 7.2 四类来源归纳（全字段）

| 来源类 | 判据 | 代表字段 | provenance |
|--------|------|---------|-----------|
| **A 真设备读数** | sysctl/gestalt/getattrlist/IOKit 实读 | m157(memsize) m251(crtime) m132/m166/m158(机型) m149(boottime) | 底层 API,值随硬件/系统 |
| **B SDK默认占位** | m307 源码 0/5/7 | m4/m18/m123/m126-136/m161/m253/m256/m303 | SDK 常量,非设备,所有机相同 |
| **C app级常量/派生** | 跨设备恒定 | m129/m138/m314 | 见 7.3 |
| **D 会话/时间/计数** | 每启动或每请求变 | m148-150/m155/m175/m312/m320/m324/m332 | 运行时生成 |
| **E 服务端回填** | 响应写回 | m27(=a8 dfp) | 服务端算 |

### 7.3 常量的确切来源（"为什么填这个值"）

| 常量 | 值 | 来源(已查/待查) |
|------|-----|----------------|
| **m314** | `EA6BFC6F…` | ✅ **已钉死**:hook CC_MD5 溯源=`MD5("TKW39C3422")`=MD5(Apple TeamID)。运行时算,故二进制搜不到字面量。 |
| **m138** | `[5,100]` | 🟡 SDK 内置常量数组(疑 [重试次数,超时] 或版本区间),Keeta.dec 未反出语义,待 hook 填充点。 |
| **m129** | `428015897` | ✅ **已钉死(IDA 逆向)**:= corpse 的 **`magic` 字段 = SAKGuard SDK `magicNumber` 魔数**,`0x19830119` 是**硬编码默认值**(`-[SAKWindFingerprintGenerator y64bGjEh]` 写 "magic" 键;property nil 时兜底 `[NSNumber numberWithInt:0x19830119]`,加载点 `sub_10033DAB0` + asm 15954250)。0x19830119≈日期 1983-01-19,典型开发者哨兵魔数,**非密码学量、非设备特征**。两机相同=编译期 SDK 魔数。(0x33655cb 只是数据段 DCQ 打包副本,非指令即值。) |
| **a5 b1.57** | `1894370865` | ❌ **已确认非字面量(IDA)**:`0x70E9CE31` 在 Keeta.dec 无任何指令即值(MOV/MOVK/ORR/EOR/ADD… 全无),仅作 DCQ 数据块子串 ⇒ **a5 签名算法运行时计算产物**,跨设备恒定但派生逻辑分散,须运行时 hook a5 生成才能定。 |

### 7.4 未锁定字段 + 追踪路径

- **本轮新解(JSON/INT 硬约束锁 K)**:m223(配件枚举)、m311(安装戳,已 SSH 钉死来源见注⑦)、m312(593 计数)、m328(证书pin)、m307(来源映射)。
- **采集源 hook 已实现**:`tools/keeta_corpse_source.py`(冷启动 hook sysctlbyname/getattrlist/stat 家族/MGCopyAnswer/gethostuuid/uname/CC_MD5/crc32,记录 返回值→来源API,并盯 WATCH 常量)。**首跑实锤 m311 来自 fstat st_birthtime**;sysctl 面确认 m157=hw.memsize、m166=hw.machine、m14/m137=kern.version、MGCopyAnswer 返机型/屏幕/artwork。
- **短不透明字段**(m218-220/m259/m260/m268/m269/m272/m321/m332/m333):值 3–10 字符,**密文单独锁不了 Caesar K**(无 JSON/纯数字结构约束)。值域小(空/单字符/枚举/slide),非设备身份。需在**新鲜采集窗口**(chaos new 后首启)用采集源 hook 抓 Caesar 前原值——注:多轮 spawn 后采集会走缓存/hook 不触发,须 chaos new 清缓存后一次抓全。
- **m129 已钉死** = SDK magic 魔数(见 7.3);**b1.57/m138 确认运行时构造**(IDA 无静态字面量),须 hook a5 生成才能定派生。
- **★corpse 组装函数(IDA 逆向定位,未来 hook 首选目标)**:
  - `+[o1iGcKmx t82fDfAg]`(asm 15955724)= **设备大字典本体**,在 `com.meituan.fingerprintSyncQueue` 串行队列上 dispatch_sync 采集全部字段 → hook 其返回值即可 dump 完整 m1..m333 明文(短字段值一并出)。
  - `-[SAKWindFingerprintGenerator y64bGjEh]`(asm 15954218)= 外层组装,合并大字典 + 用混淆 setter `m9OO81RE:forKey:`(=setObject:forKey:)写 magic/finger_version/utm_medium/ch/dpid/business/app_version/location/dylibs/brand。
  - Caesar 编码点在 `requestCorpse:`→`sub_100791634` 或 `d5fB4mkd:` 链路(m 名映射也在此)。
  - ⇒ 短不透明字段的确切值:hook `+[o1iGcKmx t82fDfAg]` 返回的 NSDictionary(Caesar 前明文),比爆破 K 可靠。这是 SDK = 美团 SIUA/SAKGuard(佐证 `-[SAKWindFingerprintGenerator isMeiTuanApp]`)。

### 7.5 ★ live 语义字典 ground-truth(2026-09-27 hook `+[o1iGcKmx t82fDfAg]`,`tools/keeta_corpse_dict_hook.py`)

定向 hook 采集器返回的 NSDictionary(Caesar 编码前),**用语义键名**(m 编号是后续序列化时映射的)。5.46 机实抓:
```
app_dection=AA==  batteryLevel=100  batteryState="Fully Charged"  bootTime=1789186441
cell="[{}]"  coreFileCreateTime/ModifyTime="1970-01-01 08:00:00"  cpuCore=6  cpuStyle=arm64e
cpuUsage=186.0  dm=iPhone12,1  firstlaunchtime=1790499013932  idfa=unknown  idfv=DEC3B9F2-…
installtime=1790498196720  local_time=1790499013938  locstatus=0  memory="115@3851"(MB)
mno=""  net=WiFi  os=iOS16.2  phonename=iPhone  phonenameInFile="iPhone's Mpvlovc"
root=0  sc="828,1792"  scBrightness=0.45  simstate=0  source=appstore  storage="94861@122007"
systemVolume=5  uuid=""  wifiip=192.168.5.46  wifimac=[]
```
- **`wifiip=192.168.5.46`** ⇒ 实锤本机 = 5.46(与目标一致)。
- **`root=0`** ⇒ 采集器上报"非越狱"(chaos/越狱隐藏生效;与 m294/b1.33 检测全 `-` 吻合)。
- **两种 install 时间要分清**:`installtime=1790498196720`(容器安装,=今天,chaos new 轮换)vs **m311=1789756165(Info.plist 构建戳,2026-09-18,版本常量,注⑦)**——名字像但一个变一个不变。
- **★解码空格替身规则(Agent B 定,重要)**:corpse 值里字面空格(0x20)是 `~`(0x7e)的替身,**反解前先 `replace(' ','~')` 再 Caesar**,否则含空格的结构字段(m306/m325/m328/m294/m332)解不成合法 JSON。四大字段 round-trip 逐字节复现校验通过。全部解析存 `dump/collect_plain/corpse_fields_resolved.json`。

---

## 8. spoof 覆盖分析（我们改动到所有设备/签名接口了吗？）

> 数据源:`新机之后尝试登录.chlsj`(chaos new 后重开 App 全流程,726 条 / 410 唯一接口 / **193 携带设备或签名**)。完整清单见 `ENDPOINTS_new_login.md`。

### 8.1 设备信息的传输结构（关键:一次计算,处处复用）

| 上报面 | 出现接口数 | 何时算 |
|--------|-----------|--------|
| **mtgsig 头(a5/a8/a9)** | 挂在**几乎所有** Keeta API(193 个里绝大多数) | a8/a9/dfp **启动算一次→缓存**(outidinfo 钥匙串 + 内存),后续请求**复用**;a5 每请求重签但采集体缓存 |
| **/v5/sign corpse body** | 1(仅 /v5/sign) | 每次 /v5/sign 重新组装 |
| **新鲜采集上报** | /fingerprint/v1/info/report、/uuid/oversea/ios/register、dd/config/alita/checkUpdate、h-eu/horn_ios/mergeRequest | 启动期 |

⇒ **决定覆盖的不是"改了多少接口",而是"有没有改到那一次启动期计算"**:改中启动计算 → 所有下游 mtgsig 复用即带假值;没改中 → 处处复用真值。

### 8.2 我们的 spoof 实际覆盖面

现用 spoof = **hook libz `deflate` + 在压缩缓冲里替换机型串**(`iPhone12,1→iPhone11,8`、`N104AP→N841AP`)+ 单独的 m251/m157/m333 spoof 脚本。

| 上报面 | 覆盖? | 说明 |
|--------|-------|------|
| /v5/sign corpse body 的机型串 | ✅ | 该次 deflate 缓冲被改 |
| **a5/a9 内的机型串** | ⚠️ 部分 | a5/a9 生成时内部 zlib 也过 deflate → **机型串会被同一 REPL 改到**;但**仅机型串**——`m157(memsize)/m251(crtime)` 这些硬件熵 REPL 没匹配,a5/a9 里仍是**真内存/真创建时间** |
| **文件系统时间戳 m251** | ❌ | m251(数据卷crtime)由 getattrlist 直读,deflate REPL 不匹配、chaos 只改 stat 层洗不掉;真 per-device(双机验),要改须 hook 采集器或改磁盘。**m311(App构建戳)也走 fstat 不覆盖,但两机相同=版本常量,不影响识别** |
| **m332 WebRTC 公网 IP** | ❌ | STUN srflx 绕过 HTTP 代理直连,**即使 App 走 Charles/住宅代理,m332 仍泄漏真实公网 IP(v4+v6)** → 服务端拿到真出口 IP。换网络出口时必须一并封 WebRTC/STUN(禁 UDP/改 STUN),否则代理白换 |
| **a8/dfp** | ❌ | 服务端回填 + 钥匙串缓存,非客户端 rewrite 目标 |
| **第三方 SDK(adjust)** | ❌ | `analytics/consent.adjust.com` 带自采设备字段 + 自己的 sign,**不过我们的 hook**,独立设备图谱 |
| **Incognia** | ⚠️ 本次未触发上报 | 本 chlsj 里 Incognia **只被 horn 拉了配置**,`events/v3` 自采上报**未出现**;它触发时走**自有 SDK 编码**(非 libz deflate 主路径)→ 大概率**不覆盖** |

### 8.3 结论

**没有全覆盖。** 现 spoof 是"机型串级"替换,存在四个缺口:
1. **a5/a9 里的硬件熵(memsize/crtime)未改**——只改了机型串,内存/创建时间仍真;要一致必须叠加 m157/m251 spoof 且覆盖 a5/a9 的 zlib 缓冲。
2. **第三方 SDK(adjust)独立上报**,完全在我们 hook 之外。
3. **Incognia 自采通道**(触发时)走自有编码,deflate hook 够不到。
4. **★m332 WebRTC 泄漏真实公网 IP**:STUN srflx 绕 HTTP 代理,即使走 Charles/住宅代理仍上报真出口 IP(120.35.98.81,=响应 clientIp)。换网络出口时不封 WebRTC/STUN,代理白换。

> **但对"换 dfp"这个目标,缺口是 moot 的**:已实测单/多字段 spoof 后 dfp 不变(服务端模糊融合,§5/§6),补齐这些接口也换不到新 dfp。缺口真正影响的是**字段级一致性**——改了机型没改内存/没改 Incognia,会在服务端融合里留下**跨字段/跨SDK矛盾**,反而比不改更可疑。**可靠换机仍只有真换物理机**。

---

## 9. 逐步实验日志（换 dfp 到底靠什么）

**假设**(用户):partial spoof 失败是因为只改了部分接口/字段;若"所有上传设备字段全改一致 + chaos new",服务端应下发新 dfp。

### Step 1(2026-09-27,`tools/keeta_consistent_spoof.py`)——客户端字段全改一致
在 5.46(${KEETA_SSH_PASSWORD})上:chaos new(全 ID+钥匙串轮换)+ 统一 spoof 把 per-device 硬件熵在**所有上传面**改成同一套假值:
- corpse(Caesar 面):m157 memsize `4038836224→4038799360`(K=73)、m251 crtime 14 条平移(K=91)
- a9/a5(明文 zlib 面):memsize 明文改 23 处
- 未登录冷启动跑 /v5/sign。

**结果:响应 `dfp = aee320…`(不变)**,clientIp=`120.35.98.81`(真实 IP,本步未动)。
**判定:假设证伪(客户端字段维度)。** 在干净未登录 + 全一致伪造下服务端仍重识别 → **决定 dfp 的锚不在客户端上传的设备字段**。唯一未变量 = 真实公网 IP + Incognia 独立通道 + 服务端首见融合。这次排除了"之前没改一致"的疑点。

### Step 2(待做)——换网络出口 + 封 WebRTC
下一步:保持 Step1 的全一致 spoof,**叠加换真实公网 IP(住宅代理/换网)+ 封 WebRTC/STUN(掐 m332)**,未登录跑 /v5/sign。若 dfp 变→锚是 IP;若仍不变→进 Step 3 中和 Incognia。

### Step 3(待做)——中和 Incognia
再叠加阻断/伪造 Incognia(installationId + events/v3 + App Attest),未登录跑。逐步加变量精确定位决定项。

### Step 2a(2026-09-27,`tools/keeta_step2_ip_spoof.py`)——封 WebRTC + 改 payload IP(未换真 IP)
在 Step1 全一致基础上叠加:m332 WebRTC(STUN UDP 拦截 32 次→拿不到候选,m332 未上报)、m156 本地IP `192.168.5.46→10.20.30.100`。仍 chaos new + 未登录。
**结果:响应 dfp = aee320(不变),clientIp=120.35.98.81(真实 L4 源 IP,本步未换)。**
**判定:payload-IP + WebRTC 维度也证伪。** 服务端用的是**自己在 TCP 层看到的真实源 IP**,不是 payload 上报的 IP → 改 payload IP 无效。剩余锚 = **L4 真实出口 IP + Incognia + 服务端融合/首见**。
⇒ **真正的 Step 2 必须用代理/换网改 L4 出口 IP**(需用户提供住宅代理或换网络);否则无法验证 IP 轴。或先做 Step 3(Incognia)。

### ★ IP 轴排除(2026-09-27,用户逻辑纠正)
**IP 不是 dfp 的区分锚**。铁证:两台手机同一局域网(192.168.5.45 / .46)= 同一 NAT 公网出口,但 dfp 不同(d3ec07 vs aee320)。**同 IP 能区分两台设备 ⇒ 区分信号必非 IP**。故 Step2 的"换真 IP"路线降级——IP 至多是融合里的弱信号,不是决定项。真锚必须:①区分同IP下不同物理机 ②扛过 step1+step2a 全部客户端伪造 ⇒ 指向**客户端 payload 之外的 per-device 信号 = Incognia 独立设备图谱**(+ 服务端机型组合/首见融合)。转 Step 3。

### Step 3 + 双机 diff(2026-09-27,`tools/keeta_step3_incognia.py` / `keeta_dual_capture.py`)——推翻"单一隐藏锚"
- **Step3(Incognia 中和)无效**:冷启动窗口 Incognia **休眠**(nil_token=0/断网=0,hook 没触发)→ 说明冷启动 /v5/sign 不经 Incognia;不能据此判 Incognia。
- **m304 双机对比:两机密文完全相同(`' { !)`)= 未登录默认值,非 per-device 判别锚**,排除。(14位`10000057339063`是登录后才有)
- **a9 双机 diff(设备A d3ec07 vs 设备B aee320):两机在大量可见信号上本就不同**——memsize(4038852608 vs 4038836224)、OS(16.1.1 vs 16.2)、内核(22.1 vs 22.2)、运营商(电信 vs unknown)、**WiFi BSSID(cc:29:bd:e9:ea:7c/CMCC-zX9U_5G vs `-`)、GPS(118.138,24.496 vs unknown)**。
- **★结论推翻"必有单一隐藏锚"**:两台机可见差异巨大,服务端区分它们**不需要隐藏锚**。step1-3 失败的真因:我们只改了 **memsize+crtime+IP 共 3 个信号**,原封留下 OS/内核/机型/磁盘/屏幕/运营商/区域/m311/**WiFi BSSID/GPS**/首见历史等 **~97 个信号** → 服务端模糊融合用剩下的把设备B聚回 aee320。
- **"全改一致就够"方向对,但"一致"必须是整套 ~100 信号 + 位置(WiFi BSSID/GPS),不是只改 memsize/crtime**。最大的未动强信号 = **WiFi BSSID + GPS(位置锚,a9 内)**——这是"同IP区分设备"里 IP 之外的维度。

### ★ crtime(m251) 机制彻底钉死(2026-09-27,root 实测 setattrlist)
- **他读哪些文件/什么时间**:getattrlist(ATTR_CMN_CRTIME) 逐读 21 路径;真锚=数据卷顶层目录(inode 2/18/47/55…)crtime=**2026-06-28 01:45:59(纳秒唯一=数据卷恢复时刻)**:`//private/var`、`/var`、`/private/var/mobile`、`.../Library`、`.../Preferences`、Carrier Bundles;其余=OS密封卷(2022-12-02/2023-01-16常量)+容器metadata(2026-09-26会变)。
- **为什么 chaos 改不成(root 工具实测,crtime2_ios)**:**iOS 上 `setattrlist(ATTR_CMN_CRTIME)` 一律 EPERM(root 都不行,连自建可写文件都 Operation not permitted)**——macOS 的 SetFile -d 能改,iOS 把该 API 封了。故 chaos 只能 patch 内核 vnode 时间戳字段(stat 读的层),而 App 用 getattrlist 读磁盘 APFS inode create_time,chaos 够不到;+ namespace 隔离(chaos 进程改的 Keeta 看不到)。
- **要真改只剩**:①卸载数据卷改 APFS 磁盘 b-tree(极危险);②上传层 deflate-spoof(已做,step1)。**但两者对 dfp 都无效**(step1 实测 m251 spoof 后 dfp 仍 aee320)——crtime 只是 ~100 信号之一。工具:`/tmp/crtime.c`(getattrlist/setattrlist,xcrun+ldid+jbctl trustcache add via jbroot 路径运行)。
