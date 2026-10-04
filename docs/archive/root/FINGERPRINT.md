# Keeta / 美团 SAKGuard 指纹采集面分析

> **2026-10-02 原生更正**：b16 是 SDK 上报调用次数及相对时点，三组分别对应 `/v5/sign`、`/fingerprint/v1/info/report`、`/v5/device-info`，不是加速度/陀螺仪。b17 计数 POST 签名前置调用，b18 在 SDK userID=nil 时递增。见 [原生写入与新任务对照](../../research/B_COUNTERS_RENDER_20261002.md)。

> **2026-10-01 字段表更正**：第一节已按实际抓包与当前实现修订。
> `a3=20/25` 在同一个 App/SDK 版本下均出现，不能称作平台号或版本升级标志；
> `a1` 不是已证明的每设备唯一 UUID，`a10` 不是每签递增计数。
> 当前字段来源、已验证范围、版本检测和更新命令见
> [协议更新流程](../../PROTOCOL_UPDATE.md) 与 [字段恢复状态](../../MTGSIG_FIELDS_STATUS.md)。
> 后续章节保留历史实验上下文，不表示其中所有推测已在当前设备重新验证。

> 配置生效续证：`observe-config` 分开观察 Horn 回调、storage 写入和 provider 加载。刷新路径 304/source=4 无回调；正常启动先读取存储使 provider 20→25，约 3.5 秒后 304/source=5 有成功回调与同值写入，之后未见重载。完整时序已观察，不能把收到响应、写入和激活混为一谈。相关 Python 67 项、JavaScript 4 个案例通过，完整证据见上述协议更新流程。

> 2026-09-28 核验更正：本文含历史猜测，密码与注册状态以
> [A9_PROVIDER_NOTES](../A9_PROVIDER_NOTES.md)、[LOCAL_ID_RESEARCH](../LOCAL_ID_RESEARCH.md)、`docs/ENVELOPE_SDK.md`、
> [CORPSE_CODEC](../CORPSE_CODEC.md) 和 `OFFLINE_CHAIN_AUDIT.md` 为准。本地 a8 不是 SHA224；
> envelope 支持三种 CBC 模式，RSA 封装的是 key XOR 设备 mask；未证实完整注册/发码成功。

> 目的:**研究大厂风控 SDK 采集了哪些设备信息**(学习采集面与思路),非绕过风控。
> 数据来源:真机 mtgsig 样本 + `a5` 采集 blob 字节级解密(算法见 `mtgsig/mtg_crypto.py`)。
> keeta 与美团国内(`com.meituan.imeituan`)**同一套 SAKGuard/SIUA,字段结构 100% 一致**,仅常量不同。
> 更新:2026-09-22。

---

## 全景:一次请求里有三类指纹

| 载体 | 位置 | 内容 | 解密状态 |
|---|---|---|---|
| **mtgsig 头** | HTTP header `mtgsig` | 签名 + 设备静态指纹字段 a0–a10 | ✅ 明文(JSON) |
| **a5 采集 blob** | mtgsig 内 `a5` 字段 | 运行时采集的设备/环境/行为指纹(**风控主数据**) | ✅ 已解密 |
| **a9 加密指纹** | mtgsig 内 `a9` 字段 | `crc32 + base64(CBC(zlib(指纹JSON)))`,块密码 16B 分组(域内=自定义 Feistel);密文体 512B=32×16 | 🔶 **算法已确认**(见「七」),密钥=keeta 专属 **v73 表**(运行时物化,静态/堆扫描均未驻留);拿到 v73 即可纯离线解密 |
| **登录 fingerprint** | `userriskcheck` body 的 `fingerPrintData`(encryptVersion=3) | **RSA-1024-OAEP(随机会话密钥) + `=` + AES(会话密钥, 设备数据)** 混合信封;实测 part1=128B(RSA)+ part2=1600B(AES) | 🟡 **可解(更正 2026-09-28)**:AES 层是**标准 AES**,会话密钥虽随机但明文传入 `AES_encrypt`(见「七·标准AES直取密钥」),hook 即得 → 已抓的信封可解;此外**定位/corpse 等固定 key 指纹(`34281a9dw2i701d4`/`meituan1sankuai0`)离线通解**。仅"无任何抓取、凭空解他人随机信封"需服务端私钥 |

> 服务端实际用于风控评估的是 **a5 明文 + a9 + device_id + IP + incog-token** 的组合。
> **重大更新(2026-09-22)**:冷启动 hook `libz` deflate,抓到 SAKGuard 全部采集通道的**明文**,
> 见「五、实测:完整设备采集明文」——这才是"收集了哪些设备信息"的直接答案。

---

## 一、mtgsig 头字段 a0–a10 与 x0（2026-10-01 更正）

下表限定为已观察的 Keeta 原生 `a0=2.5、x0=2` 布局。同名字段在 `x0=4` 等其他布局中不能套用这里的解释。

| 字段 | 语义 | 样本值 / 说明 | 依据 |
|---|---|---|---|
| a0 | 协议版本 | keeta `2.5` / 国内 `3.0` | 确认 |
| a1 | 应用配置及密码派生输入 | 当前来自主 App Info.plist 的 ak，经 SDK getter 传入 provider；UUID 形态不代表设备唯一 | 当前原生 getter、ak 和签名 a1 逐字一致；原始字节用于 K/mask/a5/a9 |
| a2 | 请求签名 | HMAC-SHA1→a2Mix→替换→pass1/2，绑定 method、canonical URL、Body UTF-8 前 16,200 字节及完整 payload；实际请求体不截断 | 原生消息拷贝及字符跨界已验证；原来的 3 条 bio 差异修复，566 条原生布局完整匹配 |
| a3 | SDK provider 配置参数；参与 a5 seed 与 a2 | 真机已观察对象 +0x58 默认 20，配置处理成功后变为 25；同 App/build 可出现两者 | AES-CBC 配置中的 a3/salt 与原生对象一致，shift=(a3+11)%36；不能只凭 a3 选择 salt/profile |
| a4 | 请求时间戳(秒) | 每请求当前时间 | 确认(`oracle.go`) |
| a5 | 采集 blob | 见「二」,`base64(RC4变体(zlib(采集JSON)))`,密钥=`(a1+a3+a4)ASCII ^ k2buf` | 确认 |
| a6 | SDK 原子状态位集合，进入 a2 payload | 全局整数通过原子 OR 累积状态，原生 getter 读取后装配；当前样本为 0 | 已证开发团队/PIC 绑定校验失败→S=8→累计 0x01/0x02；另含资源完整性/兼容性及查询错误，见 NATIVE_FIELDS，完整枚举仍有边界 |
| a7 | 注册阶段的 XID | 首次请求是 `main(1/2)` 生成的本地候选；`/fingerprint/v1/info/report` 返回 `data.result` 后，后续 mtgsig.a7 使用该服务端 XID（落盘 `.mtg_dfpid_...` 的 `xid`） | 抓包时序，见 `REGISTRATION_ID_STAGES.md` |
| a8 | 注册阶段的 DFP | 首次请求可能是本地缓存 dfpID；`/v5/sign` 返回 `data.dfp` 后，后续 mtgsig.a8 使用该服务端 dfp | 抓包时序，见 `REGISTRATION_ID_STAGES.md` |
| a9 | 加密的 SIUA 缓存画像 | CRC32 + base64 + CBC + zlib；已验证 AES/Twofish/修改 MDS 的 Twofish，存在周期刷新 | 566 条逐字节往返；profile 与 a5 独立识别 |
| a10 | 会话签名参数 | `"3,N"`；当前原生启动 `srand(time(NULL)); N=rand()%254+1`，首段直接写 3；N 参与 HMAC，与 b2 独立 | 原生初始化与输出已验证；既有会话仍保留自己的 N |
| x0 | 布局区分输入 | 当前原生路径直接写常量 2；另有 x0=4 的不同结构，其中 a2 为整数、a3/a6 含义也不同 | 当前原生写入已证；其他布局不能套用本表 |

---

## 二、a5 采集 JSON —— 风控采集主数据(实测解密)

`a5` 解开后是一层 JSON,顶层 `b1–b25`,其中 `b1` 是嵌套的**设备指纹主体**。
下表为 keeta 真机 + 国内真机双样本对照(值取实测)。

### 顶层 b* 字段

| 键 | 语义 | keeta 实测 | 国内实测 | 依据 |
|---|---|---|---|---|
| b1 | 设备指纹主体(嵌套 JSON,见下) | (见下) | (见下) | — |
| b2 | **签名序号**,每次签名 +1(服务端不校验,纯拟真) | 19 | 202 | `oracle.go` |
| b3 | **a5 采集序号**,递增;**服务端校验 a5,改 b3 即 403** | 1 | 1 | `oracle.go` |
| b4 | bundleId 包名 | `com.sankuai.sailor.ifooddelivery` | `com.meituan.imeituan` | 自证 |
| b5 | app 版本串 | `3.12.401` | `12.64.203` | 自证 · 交叉(m144) |
| b6 | app 版本号(int,=b5 去点) | `312401` | `1264203` | 自证(3.12.401→312401) |
| b7 | app 启动/安装时间戳(秒) | 1790040379 | 1787559337 | 自证(Unix 秒) |
| b8 | 当前时间戳(秒),真机 a4≈b8+offset | 1790040379 | 1787562278 | `oracle.go` |
| b9 | 时间戳(秒) | =b8 | =b8 | 自证 |
| b10 | SIUA/SAKGuard SDK 版本 | `5.21.10` | `6.7.12` | 自证 · 交叉(m152) |
| b11 | SDK 版本(同 b10) | `5.21.10` | `6.7.12` | 自证 |
| b12 | 端/平台标志(两样本恒 2) | `2` | `2` | 标志?(疑 iOS 端类型) |
| b13 | 计数(疑已采子项数) | `2` | `51` | 标志?(待反编译) |
| b16 | **SDK 上报记录**：前三组为次数/最近调用相对秒/最近 HTTP200 回调相对秒 | `[0,0,0],[1,0,0],[0,0,0],1` | `[0,0,0],[2,1801,1801],[1,22,23],0,[9,2701,2701],0111` | 当前三组结构已有原生写入证据；旧样本额外后缀不在本次结构验证范围 |
| b17 | 计数 | 18 | 153 | 标志?(待反编译) |
| b18 | 计数(国内≈b2 值) | 0 | 202 | 标志?(疑签名序号镜像) |
| b20 | 计数 | — | 50 | 标志?(待反编译) |
| b21 | 时间戳(秒) | — | 1787562278 | `oracle.go` |
| b22 | 区域事件历史，值为距 SDK 启动的累计毫秒 | `[{"BR":"867"}]` | — | NativeBridge.regionMonitor/getRegion，见 [REGION_PATH](../REGION_PATH.md) |
| b23 | 设备标识串(base62,14 字符) | — | `OLLpgcNz0O896E` | 自证(格式) · 语义待反编译 |
| b24 | 设备标识串(base62,36 字符) | — | `daVFbMhHFtbhr2hNK9kDLtzQvg5K0ZZz6W3h` | 自证(格式) · 语义待反编译 |
| b25 | 标志位 | — | 0 | 标志? |

### b1 内层(设备指纹主体)

`b1` 内含数字键槽 `1–14`、`33`、`44`、`55–58`、`100`。两样本里 `1–14`/`44` 多为空串
(该 boot/隐私态未填充,但**槽位存在**=SDK 预留的采集面):

| 键 | 实测 | 含义 | 证据 |
|---|---|---|---|
| b1.1–14 | 本样本多空 `""` | 分项设备属性槽(按位填充,本 boot 未填) | — |
| b1.33 | 见下 | **环境/风控检测子对象** | 见「b1.33」 |
| b1.44 | 空 | 预留槽 | — |
| b1.55 | keeta 1055422178 / 国内 3010776750 | 数值指纹(每设备不同) | 标志?(待反编译) |
| b1.56 | 0 | 标志 | 标志? |
| b1.57 | `1894370865`(**两设备一致**) | 固定值/编译期常量(非设备相关) | 自证(跨设备恒定) |
| b1.58 | 1790040379912 / 1787562278395 | **毫秒时间戳** | 自证(Unix ms) |
| b1.100 | `1.1.10`(国内样本) | 子模块版本 | 自证 |

### b1.33 环境检测项(风控核心:反越狱/反代理/反调试)

子对象键 `0–16`(共 17 槽),三个样本(keeta / 国内 / m294)**完全一致**,大量为空或 `-`:

| 键 | 实测值(三样本一致) | 说明 |
|---|---|---|
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

> 诚实说明:三个样本(含 m294)的 `b1.33` **逐字节相同且几乎全空**——采集面(17 个检测槽 + schema 版本 23)清楚,
> 但**每个槽对应哪项检测**(越狱/代理/调试/注入…)在明文里看不出,不臆测顺序;
> 要钉死需反编译 SAKGuard 的 `b1.33` 填充函数。空值说明真机检测结果走了 a9 加密通道或另有开关,
> 非本明文所能定。

---

## 三、登录 fingerprint(userriskcheck,960B)

- 上报形态:`{"encryptVersion":"3","src":"1","fingerPrintData":"<base64 密文>"}`(实测 `128` 通道)。
- 密文 device-stable(登录与店铺 API 复用同段),外层 SAKGuard AES 加密。
- **明文采集面 = 「五」的 m 系列设备指纹**(实锤:m12=`1647261C-…`=`login_state.json` 的 device_id;
  m153=`0000…228`=uuid/csecuuid)。即登录风控读的就是这 85 项设备信息 + 环境检测。
- 它是**风控读取的输入**,不是可绕过的校验。详见 `LOGIN_ANALYSIS.md`。

---

## 五、实测:SAKGuard 完整设备采集明文(冷启动 hook libz)

方法:frida spawn 冷启动 + jbctl 放行 + hook `libz` 的 `deflate`/`compress2`(native,不碰签名 IMP → 不触反篡改),
dump 压缩前的明文。SAKGuard 在启动期把设备信息压缩上报,一次冷启动抓齐全部采集通道。
脚本:`tools/keeta_deflate_recon.py`。样本设备:Uisz's iPhone(iPhone 11 / iPhone12,1 / iOS 16.1.1)。

### 通道 A —— m 系列完整设备指纹(85 字段,= a9 / 登录 fingerprint 的明文采集面)

这是**最全的一套设备画像**。下表为**全部 85 字段,一个不省略**,含义按证据分级:
- **API** = 冷启动 hook 系统 API 抓到该 API 返回**此值**(铁证,`tools/keeta_api_recon.py`,数据 `dump/collect_plain/api_evidence.json`)。
- **自证** = 值的格式/内容唯一确定含义(UUID/IPv6/内核串/时间戳/坐标/JSON)。
- **交叉** = 与其它字段或通道**同值**互证。
- **标志?** = 值已确认,但为 0/1/2 类内部标志,精确语义需反编译 SAKGuard 填充代码(**不臆测**)。

| 字段 | 实测值 | 含义 | 证据 |
|---|---|---|---|
| m1 | `0` | 内部标志(疑越狱/环境检测位) | 标志? |
| m2 | `0` | 内部标志 | 标志? |
| m3 | `Keeta` | app 名 | 自证 |
| m4 | `` | 空(未采集项) | — |
| m5 | `Uisz's iPhone` | 设备名(用户设置的显示名) | 自证 |
| m6 | `120619008` | 当前进程驻留内存字节 | task_info(MACH_TASK_BASIC_INFO).resident_size |
| m7 | `1.0` | 采集 schema 版本 | 标志? |
| m8 | `[{"mcc":"460","mnc":"11"}]` | 运营商 MCC/MNC | 自证 + 交叉(CTCarrier) |
| m9 | `中国电信` | 运营商名称 | **API**: `CTCarrier.carrierName` |
| m10 | `0` | 内部标志 | 标志? |
| m11 | `B00AC324-2E3D-4E47-AE78-3DFB7F2F393B` | SAKGuard 持久 UUID(Keychain,非 IDFV) | 自证(UUID) |
| m12 | `1647261C-835B-4C05-98C2-57E5D0BE6595` | **IDFV** identifierForVendor | 交叉(=`login_state` device_id) |
| m13 | `0` | 内部标志 | 标志? |
| m14 | `22.1.0` | Darwin/系统 build 版本 | 交叉(m137 内核 22.1.0) |
| m15 | `0.000000` | GPS 经度(未授权→0) | 自证(坐标) |
| m16 | `1` | 能力/检测位 | 标志? |
| m17 | `1` | 能力/检测位 | 标志? |
| m18 | `0` | 内部标志 | 标志? |
| m19 | `0` | 内部标志 | 标志? |
| m27 | `d3ec070776b9d9495e0db077f0c6c8dc8318f568e70d386e8c8630de` | 设备指纹摘要(28B=SHA-224 类) | 自证(28B hex) |
| m122 | `AA==` | base64(单字节 0x00) | 自证 |
| m123 | `` | 空 | — |
| m125 | `Alpha` | 渠道/环境标识 | 自证 |
| m126 | `unknown` | 未采集项占位 | 自证 |
| m127 | `unknown` | 未采集项占位 | 自证 |
| m128 | `` | 空 | — |
| m129 | `428015897` | 数值 ID/计数 | 标志? |
| m130 | `46011` | MCC+MNC 拼接(460+11) | 自证 + 交叉(m8) |
| m131 | `21289689088` | **可用存储字节**(≈21.3GB) | **API**: `NSFileSystemFreeSize`(≈21279M,采集时刻差) |
| m132 | `127933894656` | **存储总量字节**(≈127GB) | **API**: `NSFileSystemSize` |
| m133 | `unknown` | 未采集项占位 | 自证 |
| m134 | `unknown` | 未采集项占位 | 自证 |
| m135 | `29.850000` | 非空闲线程 CPU 使用率之和 / CPU 核数 | task_threads/thread_info，六位小数 |
| m136 | `` | 空 | — |
| m137 | `Darwin Kernel Version 22.1.0: … xnu-8792.42.7~1/RELEASE_ARM64_T8030` | **完整内核版本串** | **API**: `sysctl kern.version` |
| m138 | `[5,100]` | 电池 [状态码, 容量%] | 自证 + 二进制串 `"battery":%f,"thermal"` |
| m139 | `6` | **CPU 核数** | **API**: `sysctl hw.ncpu` / `NSProcessInfo.processorCount` |
| m140 | `arm64e` | CPU 架构 | 自证(对应 hw.cputype 0x100000C) |
| m141 | `0` | 内部标志 | 标志? |
| m142 | `0.500000` | **电量**(50%,0–1) | 自证(battery level) |
| m143 | `15` | 计数/枚举 | 标志? |
| m144 | `3.12.401` | app 版本串 | 交叉(a5.b5) |
| m145 | `appstore` | 安装来源 | 自证 |
| m146 | `0` | 内部标志 | 标志? |
| m147 | `Darwin` | 内核名 | 交叉(SIUA[4]) |
| m148 | `1790055550727.318` | 采集时刻(Unix ms) | 自证(时间戳=2026-09-22) |
| m149 | `1787189782779.004` | 首次启动/安装(Unix ms) | 自证(=2026-08-18) |
| m150 | `1790062508661` | 时间戳(Unix ms) | 自证 |
| m151 | `iPhone` | 设备 model | **API**: `UIDevice.model` |
| m152 | `5.21.10` | SAKGuard/SIUA SDK 版本 | 交叉(a5.b10) |
| m153 | `0000000000000BD1877A2D34B494FBC0662FF65F8C452A179003492613172228` | uuid/csecuuid | 交叉(=mtgsig uuid) |
| m154 | `com.sankuai.sailor.ifooddelivery` | 包名 | 自证 |
| m155 | `1790055284736` | 本次启动时刻(Unix ms) | 自证 |
| m156 | `240e:467:1b72:407c:81d:372:8545:ff8e` | **IPv6 地址**(getifaddrs) | 自证(IPv6) |
| m157 | `4038852608` | **物理内存字节**(≈4GB) | **API**: `sysctl hw.memsize` / `NSProcessInfo.physicalMemory`(0xf0bc0000) |
| m158 | `N104AP` | 硬件板型 | **API**: `sysctl hw.model` |
| m159 | `Uiszs-iPhone` | 主机名(gethostname) | 自证 |
| m160 | `iOS16.1.1` | iOS 版本 | 交叉(kern.osproductversion=16.1.1) |
| m161 | `0.000000` | GPS 纬度(未授权→0) | 自证(坐标) |
| m162 | `WiFi` | 网络类型 | 自证 + 交叉(SIUA[1]) |
| m163 | `0` | 内部标志 | 标志? |
| m164 | `zh-Hans-CN` | 语言/区域 | 自证 |
| m165 | `Asia/Shanghai (GMT+8) offset 28800` | **时区** | **API**: `NSTimeZone.name` |
| m166 | `iPhone12,1` | **精确型号(iPhone 11)** | **API**: `sysctl hw.machine` |
| m167 | `828*1792` | 屏幕分辨率(px) | 自证 + UIScreen |
| m175 | `8B10D32AE50FD62ED8EA6BC273FFA62A…`(64B hex) | 加密指纹/签名态 blob | 自证(64B hex),算法待反编译 |
| m200 | `1667453465` | Unix 秒=2022-11-03(疑固件/app 构建时间) | 自证(时间戳) |
| m249 | `iphone` | 设备品类 | 交叉(SIUA[10]) |
| m250 | `Apple` | 厂商 | 自证 + 交叉(SIUA[5]) |
| m253 | `[]` | 空数组(疑传感器/已装 app 列表,未授权→空) | 标志? |
| m254 | `0` | 内部标志 | 标志? |
| m255 | `0` | 内部标志 | 标志? |
| m256 | `0` | 内部标志 | 标志? |
| m274 | `1` | 内部标志 | 标志? |
| m293 | `dad741e26c8287cafb66a9bfff5678472e5c2c2d2c77a5f79075c725` | 设备指纹摘要 2(28B,与 m27 不同盐/输入) | 自证(28B hex) |
| m294 | `{"33":"{\"0\":23,…越狱/代理/调试检测…}"}` | 环境检测对象 | 交叉(=a5 的 `b1.33`) |
| m303 | `` | 空 | — |
| m304 | `10000057339063` | 用户 ID(美团 14 位 userId;匿名/incog 态) | 自证 |
| m305 | `828*1792` | 屏幕分辨率 | 交叉(m167) |
| m306 | `{}` | 空对象 | — |
| m307 | `{"m4":5,"m18":7,"m123":0,…}` | **各 m 字段的采集来源/耗时码映射**(SDK 自证数据来源) | 自证(key=字段名) |
| m313 | `2` | 枚举(疑 hw.cpusubtype=2/环境类型) | 标志? |
| m315 | `0` | 内部标志 | 标志? |
| m320 | `774506003` | 数值 ID/计数 | 标志? |
| m324 | `7A692C5109ED4F0EB5680CBAE52929EB01` | 会话/安装 ID(17B hex) | 自证(hex ID) |

> 说明:标注"标志?"的是 0/1/2 类内部布尔/枚举,`m307` 已给出每个字段的来源码但未公开码表;
> 要把它们逐一钉死到"越狱位/代理位/调试位…",需反编译 SAKGuard 采集函数(混淆重,单列后续)。
> 已有 API/自证/交叉三类硬证据覆盖全部**有实际内容**的字段。

### 通道 B —— SIUA 主采集数组(关联 a5/a2)

`{"0":12, "1":[16项], "2":[…], "3":{"253":5,"127":5}}`。数组 `1` 的 16 项**逐项**
(每项都能交叉到通道 A 的 m 字段,含 API 铁证):

| # | 值 | 含义 | 证据 |
|---|---|---|---|
| [0] | `0` | 越狱/模拟器标志 | 标志?(交叉 m1/m2) |
| [1] | `WiFi` | 网络类型 | 交叉(m162) |
| [2] | `0.000000` | GPS(未授权→0) | 自证 · 交叉(m15/m161) |
| [3] | `[5,100]` | 电池 [状态,容量%] | 交叉(m138) |
| [4] | `Darwin` | 内核名 | 交叉(m147) |
| [5] | `Apple` | 厂商 | 交叉(m250) |
| [6] | `中国电信` | 运营商 | **API** CTCarrier · 交叉(m9) |
| [7] | `iOS16.1.1` | 系统版本 | 交叉(m160) |
| [8] | `N104AP` | 硬件板型 | **API** hw.model · 交叉(m158) |
| [9] | `zh-Hans-CN` | 语言 | 交叉(m164) |
| [10] | `iphone` | 品类 | 交叉(m249) |
| [11] | `iPhone` | model | **API** UIDevice.model · 交叉(m151) |
| [12] | `Asia/Shanghai (GMT+8) offset 28800` | 时区 | **API** NSTimeZone · 交叉(m165) |
| [13] | `828*1792` | 分辨率 | 交叉(m167) |
| [14] | `22.1.0` | Darwin 版本 | 交叉(m14) |
| [15] | `-` | 保留/空 | — |

数组 `2` 含:越狱态、ms 时间戳、磁盘字节数(=m132)、`b1.33` 检测对象、电量、包名、版本(与 m 系列同源)。
样本 `dump/collect_plain/siua_array.json`。

### 通道 C —— fingerPrint 上报(登录风控)

`{"encryptVersion":"3","src":"1","fingerPrintData":"<base64 密文>"}`。
`fingerPrintData` 是 m 系列采集经 SAKGuard 加密后的密文(明文即通道 A)。样本 `128_deflate.json`。

### 关于 a9 离线生成

a9 的**采集内容**已随本次冷启动抓到(=通道 A 设备指纹)。若还要**离线生成 a9**(纯参数合成新设备),
仍需 dump keeta 专属 **v73 表(4256B)**:在 a9 的 zlib 输出缓冲下硬件 watchpoint,命中 Feistel 函数读其表基址。
属额外一步,与"看采集了什么"无关,可按需再做。

---

## 六、标志位的检测面(动态钉死"在测什么")

标志位(m1/m2/m16… 及 `b1.33` 各槽)的**填充在 native C 层**(不走 NSMutableDictionary,`setObject:forKey:` hook 零命中),
逐个编号无法动态定位。但换个角度——**hook 越狱/调试探测 syscall + backtrace**,可钉死这些位到底在检测什么。
脚本 `tools/keeta_syscall_recon.py` / `keeta_detect_recon.py`,数据 `dump/collect_plain/detect_surface.json`。

### 两套越狱检测函数(backtrace 定位,实测)

| 检测器 | 地址 | 手段 | 用途 |
|---|---|---|---|
| `+[UIDevice cipf_isJailBreak]` | `Keeta+0x23003b0` | `stat("/Applications/Cydia.app")` | CIPF/点评系,`dianpingPragmaOS` → `SAKBaseModel willExecuteHTTPRequest` 挂 HTTP 头 |
| SAKGuard 文件枚举器 | `Keeta+0x32b018` / `+0x32b248` | `NSFileManager fileExistsAtPath:` 遍历越狱特征表 | mtgsig 指纹采集(同 a2 所在 0x39xxxx/0x3axxxx 簇) |

### 实际探测的越狱/环境特征(去重,一次冷启动)

| 类别 | 探测目标(样例) |
|---|---|
| 越狱 hook 框架 | `MobileSubstrate.dylib`、`CydiaSubstrate.dylib`、`libhooker.dylib`、`libsubstitute.dylib`、`/usr/lib/substrate` |
| 越狱商店/工具 | `/Applications/Cydia.app`、`/Applications/Sileo.app` |
| 越狱痕迹 | `electra.list`、`sileo.sources`、`.installed_unc0ver`、`.bootstrapped_electra`、`undecimus.list`、`/jb/jailbreakd.plist`、`libjailbreak.dylib` |
| 包管理 | `/etc/apt`、`/private/var/lib/apt/`、`/var/lib/dpkg/info/mobilesubstrate.md5sums` |
| 新增二进制 | `/bin/bash`、`/usr/sbin/sshd` |
| **动态注入/调试** | **`/usr/sbin/frida-server`**、改机插件 `DynamicLibraries/*.plist`(fakephonelib/AWZ/ALS…) |
| 反调试 | `sysctl(CTL_KERN,KERN_PROC,KERN_PROC_PID,getpid)` ×7 —— 查自身 `P_TRACED` 标志 |

> **边界(诚实)**:上面钉死了标志位**检测什么**(越狱框架/商店/痕迹/frida/调试器),检测**函数地址**也拿到了。
> 但"哪个 m 编号 = 哪项检测结果"这一步,因值在 native 混淆 `__text`(CFF+垃圾,同 a2)里拼进 JSON,
> 且**本设备明文里这些位全是 0/空**(检测结果走 a9 加密通道或被 SDK 内部消费),
> 逐个编号钉死需对 `0x32b018`/`0x23003b0` 做硬件断点级追踪(同 a2 的 watchpoint 路线,数天级)。
> 起点已备:两个检测函数地址 + 探测特征表。收益低(这些位明文恒 0),按需再深挖。

---

## 七、加密与密钥体系(fingerprint / a9 离线解密进展)

目标:分析异常流量设备时,拿到抓包的 `a9`/登录 `fingerprint` 密文即可离线解密成明文。
需要 (算法 + 密钥 + 密钥来源)。本轮冷启动/attach hook 定位到全部加密入口,进展如下。

### 加密函数与密钥派生(已定位)
| 用途 | 函数 | 备注 |
|---|---|---|
| SAKGuard 主对称加密 | `+[SAKGuardCommon encrypt:withKey:byAlgorithm:]` / `decrypt:` | fingerprint/a9 走这里 |
| CIPF AES | `-[NSData cip_aesEncryptWithKey:iv:algorithm:]` | **实测用硬编码 key/iv** |
| **会话密钥派生** | `+[TTEHKDF deriveKey:salt:info:outputByteCount:]` | HKDF(salt+info→key) |
| GCM | `+[SAKGuardCommon aes_gcmEncrypt:ciphertext:aad:key:ivec:tag:key_len:]` | |
| 密钥管理 | `+[SAKGuardCommon km_encrypt:dkData:edkToken:]` | |
| SAKGuardCommon 方法全集 | `deviceFingerprintData`/`deviceFingerprintID:`/`deviceFingerprintXID:`/`encrypt:withKey:byAlgorithm:`/`km_encrypt:dkData:edkToken:`/`sign:attachSiua:`/`aes_gcmEncrypt:…`/`checkCodesignID:fromKeyFile:` | |

### 实测:CIPF AES 用硬编码字符串 key/iv(铁证)
启动期 hook 到 `cip_aesDecrypt` 解 Horn 配置:
```
key = "meituan.sankuai."  (16B ASCII)
iv  = "meituan.com"        (ASCII, 补齐)
密文 2160B → 明文 2144B = 配置 JSON  ["\/\/private...
另一路 cip_aesEncrypt: iv = "1234567887654321" (16B ASCII 固定)
```
⇒ SAKGuard 系对称加密的 key/iv 是**明文常量**,不是每设备秘密。这为离线解密指明方向。

### 【重大发现 2026-09-22】登录 fingerprint = RSA-OAEP + AES 混合信封 → 设计上不可离线解密
实测 `fingerprint_report.json` 的 `fingerPrintData`(encryptVersion=3)结构:
```
fingerPrintData = base64(RSA_block)  +  "="  +  base64(AES_payload)
                  └ 128 字节 ────┘         └ 1600 字节 = 100×16 ┘
```
- **part1 = 128 字节** = RSA-1024 密文(用 RSAES-OAEP 封装的**随机 AES 会话密钥**)。
- **part2 = 1600 字节** = 用该会话密钥 AES 加密的设备数据(= m 系列采集面,见「五」)。
- **铁证**:
  1. 二进制内嵌 RSA 公钥:2× RSA-1024(`MIGfMA0GCSqGSIb3DQEB…QCWMddA1y8VHiRS8mOm…` 等)+ 1× RSA-2048(`MIIBIjANBgkqhkiG9w0…`),以及字符串 `RSAES-OAEP` / `OAEP_DECODING_ERROR`。
  2. part1 恰为 128 字节 = RSA-1024 输出长度;作为大整数 < 内嵌模数 N(符合 RSA 密文取值域)。
  3. part2 长度 1600 = 100×16(AES 块对齐)。
- **结论(决定性)**:会话密钥每次生成都是**随机**的,并用**服务端**的 RSA 公钥封装。→ **任何离线手段(含硬件 watchpoint 追 VMP)都拿不到"可复用的密钥"**;硬件断点最多能在一次生成时抠出**那一次的临时会话密钥**,只够解**那一条**抓包,无法解任意设备的流量。这正是大厂风控防抓包解密的标准做法(混合加密,密钥归服务端)。
- ⇒ 「拿到 key 完成解密」对登录 fingerprint **不成立**;它就是被设计成只有美团服务端(持 RSA 私钥)能解。

### a9 算法确认:crc32 + base64(CBC(zlib(指纹))),块密码=自定义 Feistel
- 与域内 `mtgsig_go/a9.go` 逐位一致的框架:`指纹JSON → zlib(level6) → Xz`;`crc=CRC32(Xz)`;`X=PKCS7(Xz)`;`blob=CBC(X, IV="0102030405060708"(16B ASCII), 16轮 Feistel)`;`a9=hex(crc)+base64(blob)`。
- 实测 keeta a9 样本:`crc32=e626c00d`,base64 体解出 **512 字节 = 32×16**,完全符合上述 CBC 分组。
- **块密码 = 自定义 Feistel(域内 sub_10011DB18 同族)**,全部密钥材料 = 一张 **v73 表**(4×256 uint32 的 T 表 + 40 个 round key,共 1064 uint32 = 4256B)。`rk(i)=v73[1024+i]`,`tn()` 查 `v73[0:1024]` 四张表 —— **不依赖 a2,是固定表**,拿到即可纯离线解密任意设备 a9。
- ⚠️ **keeta 的 v73 表 ≠ 域内 v73**:用域内 v73 解 keeta a9,CRC 不符(`e8682f16≠e626c00d`)——算法对、表不对。keeta 的 v73 是**运行时物化/混淆**的(静态 `Keeta.dec` 与运行时堆 rw- 扫描"T0 满足 byte2==byte3 排列"的候选里都无匹配;仅有标准 AES 表)。之前 IDA 在 const 看到的"标准 AES Td/Te/S盒"是 SDK 通用 AES,**不是 a9 的 v73**。
- **拿 v73 的下一步**:在 a9 生成瞬间(任一签名请求即触发)用硬件 watchpoint 抓 Feistel 读表/round key 的地址,dump 4256B → 填入 `a9.go`/`mtg_crypto` 即可离线解全部 a9。属可行的机械 dump,非密码学障碍。

### 【2026-09-22 续】a9 明文已抓 + v73 表提取受阻(硬件 watchpoint 追踪结论)
本轮用硬件 watchpoint 实攻 a9 的 key(v73 表),结论如下:
- **a9 明文已抓(安全,hook libz deflate)**:a9 生成时 zlib 输出 ~502B → 解压得 1102B 的 **SIUA 设备指纹数组** `{"0":12,"1":[...WiFi/型号/运营商/时区...],"2":[...bundle/版本/磁盘/内存/IDFV...],"3":"{\"253\":5,\"127\":5}"}`(存 `dump/collect_plain/a9_plain.json`)。502B zlib + PKCS7 → 512B = a9 密文体,吻合。**即 a9 加密的就是这份 SIUA 明文,本机可随时抓**。
- **v73 表提取全部受阻**(依次尝试,均负):
  1. 静态扫 `Keeta.dec`「T0 byte2==byte3 排列」→ 仅标准 AES 表,无 a9 自定义表;
  2. 运行时堆 rw- 扫(spawn 后 + a9 生成后)→ 同样只 3 个标准候选,无匹配;
  3. IV 串 `0102030405060708` 全 12 处静态拷贝下 read-watchpoint(85 线程 + 启动期高频 re-arm)→ **零命中**(a9 不从 .const 读该 IV,疑内联或另一 IV);
  4. 对 a9 **明文缓冲**下 read-watchpoint(deflate onLeave 拿到地址即 arm)→ **进程秒崩**:a9/mtgsig 的 VMP 对调试寄存器敌对(与 fingerprint 路径不同,后者 watchpoint 自测可用);
  5. a9 当标准 AES-CBC 爆破二进制窗口 key(IV=IV串/0)→ 无命中。
  6. **控制端 arm Te 表(0x33073c8)read-wp,仅在 a9 生成窗口捕获** → a9 生成多次但 Te **零命中** ⇒ **a9 不用标准 AES 表,确系自定义 Feistel + 隐藏 v73 表**;且控制端 arm 全程不崩(证明崩溃源于"在 Interceptor 回调内 arm"或"命中 a9 明文堆缓冲",非 arm 本身);
  7. a9 明文缓冲**每次 fresh malloc 不复用**(实测地址全不同)→ 缓冲复用 watchpoint 也不成立。
- **结论**:a9 算法与明文都拿到了,但**可复用的 v73 表(4256B)受 VMP 运行时物化 + 反调试双重保护**,现有 watchpoint/静态/堆扫描均取不到;**fresh a9 同实例扫描(消除 stale-sample 混淆,最终确认)**:同一进程内 hook HTTP header 抓 fresh a9(crc=dae737f3,512B),对当前内存做通用列排列扫描(720 候选 / 4832 测试)→ **仍未命中**。⇒ 排除"旧样本 vs 当前内存不一致"的可能;v73 表**要么算法与域内 Feistel 不同(致 CRC 测试失效)、要么非连续 4×256 Te 布局/运行时按需计算**——两者都需先反混淆出确切算法,而该函数是 thunk 混淆。

**通用列排列扫描(最终尝试)**:a9 生成后,in-JS 扫 rw-+模块所有 16B 对齐处、检测"任一 byte 列为 0-255 排列"的 Te 候选(不再限 byte2==byte3),得 **687 候选**,对每个测连续 v73 + round key 窗口搜(±0x4000),共 **8623 次 CRC 试解,全部未中**。⇒ **v73 不以任何标准 4×256 Te 布局驻留内存**(或每次 Feistel 调用临时物化后释放/非连续/表结构与域内不同)。

**a9 encode 路径已定位(backtrace+IDA,2026-09-22)**:a9(zlib,明文头`{"0":12,"1":["0","WiFi"...`=SIUA)生成栈 = `MOD+0x2ee694(调deflate)←0x38f990←0x38ee0c←0x2e88dc←0x340f08(sub_100340AF0, NativeBridge setSiuaCollectTime,组SIUA)`。但 IDA 反编译该路径:`sub_1003413AC` 只组 NSMutableArray;`sub_10038E5FC`/`sub_10038FC20` 是 **obfuscated thunk 链(→+8)**——与 fingerprint 路径同款 VMP 混淆。且 sub_1003413AC 调用树深度3内**无 permutation-column 常量表**⇒ **v73 表运行时物化、经指针间接访问(非静态常量)**。静态 IDA 追到混淆 thunk 即断。

**唯一剩余路径 = 对 a9 Feistel 函数做 VMP 单步反混淆**,在它 load v73 表基址的那条指令处抠地址(数据 watchpoint 命中 a9 明文即崩,只能靠受控单步)。属 a2 同级数天工程,自动化 watchpoint 手段已穷尽。⇒ a9 **本机可抓明文**,但**离线通用解密(拿表)未完成**。

### 【2026-09-27 第 8 法:Stalker 指令级追踪 —— 突破反调试墙, 但确认算法≠域内】
前 7 法全靠硬件 watchpoint(调试寄存器)/静态/堆扫描: watchpoint 命中 a9 明文即秒崩(VMP 对调试寄存器敌对),扫描定位不到运行时物化的表。**第 8 法改用 Frida Stalker**(JIT 重编译指令流插桩, 不用调试寄存器)——工具 `tools/keeta_stalker_v73.py`:
- **反调试墙已破**:hook `libz deflate` 识别 a9 的 SIUA 明文(`{"0":12` 开头), onLeave 起 `Stalker.follow` 当前线程, 对每条 `ld*` 指令 `putCallout` 记录被读地址。**全程不崩**(Stalker 非调试寄存器, VMP 的老防线失效)。**这是前 7 法做不到的**。
- **双机隔离**:另一会话逆 part2 占设备1(反复 spawn/kill Keeta 会杀本脚本 → "script destroyed")。改固定设备2(`00008030-0019702811D8402E`, jbctl proc_set_debugged 成功)后干净收网。
- **表区已定位**:压到 deflate 后 ~16k load 的 Feistel 突发窗口, 直方图现出表区(如某次 `0x10e0d5000..0x10e0d5c00`, distinct 地址 83/169/140、avg 3.6 —— 典型查表)。地址每 launch 变(ASLR/堆), 但本机可随时定位。
- **决定性结论:a9 分组密码 ≠ 域内 uint32-Feistel**。对抓到的真实 a9 密文, 用域内 `A9Cipher` 做 **窗口滑动 × 子表 24 种排列 × rk 前/后位置** 全枚举(`tools/v73_layout_solve.py`)→ **全未命中**。再看访存对齐:表区读地址中 **155/414 非 4 字节对齐**, 且**全程无 ≥12 个连续 4 字节 word 的读**。⇒ 域内是 uint32 查表, keeta a9 是**按字节访存**的另一套分组密码。**任何基于域内算法的拿表/排列都不可能解 keeta a9**——需先从 Stalker 全量(addr,value,顺序)读写轨迹**反出 keeta 自己的算法**, 才谈得上离线通用解密。这坐实了本节上方"算法与域内 Feistel 不同"的猜测。
- **净进展**:反调试墙(watchpoint 秒崩)已被 Stalker 绕过 ✅;表区可稳定定位 ✅;但离线通用生成/解密仍卡在"keeta 专属字节级算法未反出"(数天级单步反混淆), 与 a2 同级。

### 【2026-09-28 第 9 法:SM4 假设检验 —— 排除"标准 SM4+连续轮密钥", 指向 whitebox】
线索:二进制 `0x3389d20` 处驻留**标准 SM4 S-box**(与官方 16×16 表逐字节一致),且 Stalker 实证 a9 为**按字节访存**——恰是"SM4 只查 S-box、L 层用寄存器移位实现"的形态。故检验假设 **a9 分组密码 = SM4**。工具 `tools/sm4_a9_scan.py`(SM4 4×256 T-table 优化, 单块加密提速 ~4x)。
- **数据/oracle 已校验干净**:`a9 = crc32(xz)[c55315ed] + base64(密文 160B/10 块)`;`inflate(xz)=708B` SIUA JSON(`{"0":12,"1":[...`);`X=xz+PKCS7=160B` 与密文 10 块对齐;CBC/IV=`0102030405060708`(ASCII)。SM4 实现对标准测试向量(`681edf34...`)自检通过。
- **全负结果**(热区 132 窗口, 每窗口全偏移滑窗):
  - 直扫 32 连续 uint32 当轮密钥:密钥序 **BE/LE × 正序/逆序** × 分组状态 **BE/LE** × oracle **CBC/ECB** —— 8 组合共 ~1300 万次试解, **全未命中**;
  - 16B 主密钥 → 标准 FK/CK 密钥扩展 → 全未命中。
- **结论:排除"标准 SM4 + 轮密钥/主密钥以连续数组驻留热区窗口"**。与第 8 法"读地址中无任何连续 4 字节对齐 uint32 数组"互证 ⇒ **轮密钥根本不以明文连续数组被读取**。最可能是 **whitebox SM4**(轮密钥扩散进掩码查表, 内存无可提取明文密钥), 兼容"标准 S-box 驻留 + 字节级访存 + VMP"三条现象。次可能:自定义 L 线性层(致直扫失效)或轮密钥在栈上/非连续。
- **下一步(需设备)**:① 定位并 hook a9 的 SM4 加密函数, 直接 dump 其轮密钥/主密钥入参;② 或 Stalker 记录每读地址的**被读次数**, 挑"恰好=块数(10)次、32 个近邻地址"的簇 = 轮密钥区, 定向 dump;③ 若确系 whitebox, 则需全量指令轨迹提升算法(数天级)。纯离线爆破路径至此穷尽。

### 【2026-09-28 第 10 法:清缓存强制重生成 —— a9 可反复触发, 且固定 key/IV】
用户指点: a9 被磁盘持久化(平时启动不重算, 抓到头却无 deflate)。**清 keychain 身份项 + dfp plist 缓存后, app 在重注册时强制重采集+重加密 a9**。工具 `tools/keeta_a9_keyhook.py`(2222→设备2, spawn 挂起态清 keychain + 删 dfp plist 键 + hook)。
- **实证**: 一次启动内 a9 deflate 命中 **18 次**(SIUA `{"0":12` 明文, Xz 长度 149/190/503/517/543/549B) —— 死结(缓存复用致抓不到生成)已解, 现可稳定反复触发 a9 生成。
- **a9 ≠ 走 `+[SAKGuardCommon encrypt:withKey:byAlgorithm:]`**: 该 ObjC 方法在 18 次 a9 生成中**零调用** ⇒ a9 分组密码是更底层 C 函数(Feistel), hook ObjC 加密入口拿不到 key。
- **关键: a9 固定 key/IV**。重生成的 149B Xz 与既有 `xz.bin` **逐字节一致**(同明文→同密文) ⇒ 非每请求随机, **逆一次即通解所有设备 a9**(与 a5 同性质), B 工程价值坐实。
- **下一步**: 既然可反复触发, 用 Stalker 调用目标直方图定位"每块调一次、16B 进 16B 出"的 Feistel 块函数, 再 hook 它直接抓(明文块, 密文块, 密钥指针), 绕过内存盲扫。

### 【2026-09-28 第 11 法:Stalker 调用直方图定位 Feistel 块函数(候选已缩小)】
工具 `tools/keeta_a9_feistel_locate.py`(单发隔离: 只追踪首个 nb≥30 的 a9, deflate onLeave 起 Stalker call 事件, 下一 deflate/100ms 停) + `tools/keeta_a9_feistel_verify.py`(用 `Xz[0:16]^IV`=已知首块 CBC 输入验证候选)。
- **34 块 a9 干净窗口的调用直方图**(模块内偏移, 按次数): `0x2dc7ec`=171(内层轮/工具, ≈5×/块)、**`0x3a5bf8`=30(最接近块数 34, 疑 CBC 块函数, 差数落在 follow 窗口边缘)**、`0x3a83a8`/`0x3a83b4`=16、`0x30ed4b0`=13、`0x3a673c`/`0x30ed900`=10。
- **验证 hook 未坐实**: 反复 wipe/spawn/kill ~6 轮后, 设备 a9 注册流程(依赖 `/v5/sign` 网络请求)未在窗口内触发(空候选、仅 hook deflate 亦 0 命中 ⇒ 是设备状态/限流, 非 hook 代码问题)。工具逻辑正确(已知首块 oracle), 待设备冷却或换实例后, 命中即得块函数入口 + 其读取的密钥/表指针。
- **净进展**: 加密突发的候选函数集从"整个模块"缩到 6 个偏移; `0x3a5bf8` 为首选。下一步 = 设备冷却后跑 verify 命中 → dump 块函数密钥入参 → 离线复算验证。

### 设备 corpse(dfp_5.21.10_,getDeviceFingerprintString)= 确定性 AES-1840
- `getDeviceFingerprintString`(非主线程走生成/主线程读 `fingerprintStr` 缓存)返回 `dfp_5.21.10_ + base64(1840B)`,1840=115×16,连续两次重算**完全相同**(确定性)→ 固定 key + 固定 IV(ECB 或定 IV CBC),**非 RSA 混合**(RSA-OAEP 会随机)。
- 离线爆破:以二进制全部可打印串(直接/MD5/SHA256,ECB+CBC×多 IV,654k key)与前 66M 个 16 字节窗口作 AES key,**均未命中** → corpse 的 key 非内嵌 ASCII/二进制常量,系**设备派生**或需 VMP 追踪。此字段与 a9/登录 fingerprint 独立。

### 现状边界(诚实,2026-09-22 更新)
| 字段 | 可否离线解密 | 依据 |
|---|---|---|
| **a5** | ✅ 已实现 | 全局 salt + 明文 a1 → k2buf,换设备通用(前节已验证) |
| **a9** | 🔶 外层框架已确认,内层分组密码≠域内(需反出算法) | 外层 = crc+base64(CBC(zlib(fp)), IV="0102030405060708");内层分组密码**非域内 uint32-Feistel, 而是按字节访存的另一套**(2026-09-27 Stalker 访存对齐实证)。Stalker 已绕开反调试墙+定位表区, 但离线通用解密需先从读写轨迹反出 keeta 自有算法(数天级单步)。**a9 本机可抓明文; 且属设备身份, 服务端注册, 离线伪造无用(DFP 墙)** |
| **登录 fingerprint** | 🟡 可解(更正 2026-09-28) | AES 层是标准 AES, 密钥明文传入 `AES_encrypt`(hook 即得); 固定 key 指纹离线通解, 随机信封需抓取其会话密钥。见下「标准AES直取密钥」 |
| **设备 corpse** dfp_5.21.10_ | ✅ 已解(更正 2026-09-28) | 标准 AES-128-CBC, 固定 key **`meituan1sankuai0`**(之前 654k 串爆破未中, 因 key 要从运行时 `AES_encrypt` 入参读, 非静态可扫); 定位指纹另用固定 key **`34281a9dw2i701d4`** |

### 【2026-09-28 标准AES直取密钥 —— fingerprint/corpse 已解(推翻"RSA不可解")】
**方法(另一会话突破 + 本会话复核)**:app 里有一个**标准 OpenSSL `AES_encrypt` @ `Keeta+0x2d9064`,非 CFF/非 VMP**,所有对称加密最终都调它,**密钥明文躺在入参 `x2`(AES_KEY 结构: 轮数 @+0xf0, rd_key 前16B=主密钥, 按4字节小端存)**。Interceptor 直接挂不崩,读 x2 即得 key,再 hook `deflate` 拿加密前明文(corpse)、`SecKeyEncrypt`/`NSJSONSerialization` 拿信封,按线程/时间对齐。工具 `tools/keeta_aes_hook.py`/`keeta_aes_io.py`/`keeta_correlate.py`/`keeta_e2e*.py`。
- **实证(本会话复核 /tmp/e2e4.json)**: `AES-ECB(还原key)==out` **48/48 命中** ⇒ 标准 AES, key 直接可用; 主密钥恒定 = `meituan1sankuai0`(捕获 `tiem1nauknas0iau` 按4B小端还原); 另有随机会话密钥(如 `ZIWyERb6al7eakiI`, 6次)= 信封 AES 载荷。
- **实证(用户抓包)**: 定位指纹密文 → AES-128-CBC / key `34281a9dw2i701d4`(k0.k5) / IV `0102030405060708` → 明文 `{"I17":{"longitude":118.1796,"latitude":24.4908,...}}`(真实厦门定位)。
- **已固化**: `keeta_rpc.py` 新增 `POST /fingerprint/decrypt`(别名 `/fp/decrypt`): 传密文(+可选 key/iv), 不传 key 自动试 k0 密钥表, 返回明文; base64 容错(去 `\/`/空白/补位/截块) + 截断告警。往返自测通过。
- **k0 密钥表**(标准 AES-128, IV=`0102030405060708`): `meituan1sankuai0`(corpse/m系列)、`34281a9dw2i701d4`(I17定位)、`meituan0sankuai1`、`$MXMYBS@HelloPay`、`Maoyan010iauknaS`、`X%rj@KiuU+|xY}?f`。
- **边界**: 仅"无任何抓取、凭空解他人**随机会话密钥**信封"仍需服务端 RSA 私钥; 固定 key 指纹离线通解, 随机信封抓到其 `AES_encrypt` 入参即可解。**注意: 此 0x2d9064 标准AES ≠ a9 的 ARX Feistel(实测无 a9 输入块经此), a9 仍缺 v73。**

**关键区分**:a9 走**对称固定表**(可离线),登录 fingerprint 走**非对称混合信封**(不可离线)——这是两种不同的加密设计,不能混为一谈。

### 登录 fingerprint 生成链(IDA 静态 + 主动触发实证)
```
风控请求 -[MSIDefaultIMPV2Context execute_getRiskControlFingerprint:]
  → -[MSIDefaultIMPV2Context generateFingerprintData:]
  → +[SAKFingerprintGenerator sharedGenerator] (dispatch_once 单例)
  → -[SAKFingerprintGenerator requestCorpse:] (转发给 dfp=SAKGuardDeviceFingerprint 单例)
  → -[SAKGuardDeviceFingerprint requestCorpse:/requestSyncCorpse]  ← 实际生成+加密(VMP 内联)
存储: +[SAKGuardLocalIDKeychainStorage FingerprintDataBeforeUpdate/Update] → Keychain 缓存(lastCorpse)
```
- **可主动生成(不用登录 UI)**:frida 调 `[[SAKFingerprintGenerator sharedGenerator] requestSyncCorpse]`
  同步返回 `{fingerprint="<base64 密文>"}`(实测拿到)。`lastCorpse` 读缓存,返回同一密文。
- **加密内联 VMP(实测)**:主动 `requestSyncCorpse` 生成 fingerprint 全程,`encrypt:withKey:byAlgorithm`/
  `cip_aesEncrypt`/`deriveKey` **零命中**,只有日志 deflate。⇒ fingerprint 加密不走 ObjC 层,
  和 a9/a5/a2 一样在 NativeBridge VMP 内联。`TTEHKDF.deriveKey` 是别处用途,与 fingerprint 无关。
- **触发时机答疑**:fingerprint 有 Keychain 缓存(`lastCorpse`),登录发码时多半直接读缓存,
  hook 发码那一刻确实追不到生成。但 `requestSyncCorpse` 可主动实时重算 → 想抓生成随时能触发,
  只是加密在 VMP,ObjC hook 抓不到 key。

### 决定性边界:mtgsig 字段加密内联在 VMP(ObjC hook 无效)
实测:冷启动 + attach 运行期(app 浏览/进店/进活动页)全程,`encrypt:withKey:byAlgorithm`、
`cip_aesEncrypt`、`deriveKey`、`gcm` 这些**对外加密 API 全部零命中**(只有启动早期一次
`cip_aesDecrypt` 解 Horn 配置)。⇒ **mtgsig 内部字段(a9/a5/a2)的加密与 a2 一样内联在 NativeBridge VMP**,
不走可 hook 的 ObjC 方法。`SAKGuardCommon.encrypt:withKey:byAlgorithm` 是 SDK 对外通用加密(供业务/配置用),
不是 mtgsig 字段的加密路径。
⇒ **a9 的 key/mode 只能像 a2 那样用硬件 watchpoint 追踪 VMP 执行**(见 [[keeta-mach-hw-watchpoint]]),
ObjC hook 与"清缓存重启"都拿不到(因为加密不在 ObjC 层)。这是数天级专家工程。

### 要完成离线解密还需(下一步,均需特定触发时机)
1. **fingerprint 会话密钥**:走一次邮箱登录发码,hook `TTEHKDF deriveKey:salt:info:` 抓 (salt, info, 输出key) + `encrypt:withKey:byAlgorithm:` 抓 (明文, key, algo)。判定 salt/info 是否全局/明文可推 → 决定能否离线。**有副作用**(可能需登出当前账号 + 触发服务端风控)。
2. **a9 key**:清除 a9 缓存(MMKV/Keychain)或首装态冷启动,hook `encrypt:withKey:byAlgorithm:`/`cip_aesEncrypt` 抓 a9 加密的 key+mode;或对 `sign:attachSiua:` 组装 a9 处做硬件断点(避开会被杀的 IMP hook)。
- 工具:`tools/keeta_crypto_recon.py`(冷启动完整抓)、`tools/keeta_genfp_recon.py`(主动触发)、`tools/keeta_detect_recon.py`。

---

## 四、风控采集思路小结(学习向)

大厂 SAKGuard/SIUA 这类风控 SDK 的采集设计:
1. **分层冗余**:同一指纹在 a5(明文压缩)+ a9(加密)+ 登录 fingerprint 三处冗余采集,交叉校验难伪造。
2. **注册身份 + 动态混合**:a1 稳定；a7/a8 在首次注册时先用本地候选，收到服务端 XID/DFP 后稳定复用；动态部分为 b2/b3/b8 时间戳与序号(防重放)。
3. **序号绑定**:b3 采集序号递增且被服务端校验(改则 403),防止 a5 被静态重放/篡改。
4. **SDK 上报状态**：2026-10-02 已纠正 b16 的传感器猜测。当前三元组由三类 SDK 上报调用和 HTTP200 回调更新；服务端具体规则仍须按对照验证，不能凭该字段宣称真机/模拟器检测结论。
5. **环境检测集中在 b1.33**:越狱/代理/VPN/调试/注入/模拟器一组布尔位,喂给服务端风险模型。
6. **签名绑请求**:a2 只校验前 8 字节但绑 method+path+body,防跨接口/改包重放。
7. **服务端最终裁决**:客户端只负责"如实采集",拉黑/放行由服务端 `userriskcheck` 综合 IP+设备+指纹判定(本设备被 `user_risk_deny`)。

---

## 复现方法

```bash
cd keeta
python3 - <<'PY'
import json,sys; sys.path.insert(0,"mtgsig")
import mtg_crypto as C
d=json.load(open("/tmp/keeta_K.json")); mt=d["mtgsig"]
k2=bytes.fromhex(json.load(open("mtgsig/keeta_const.json"))["k2buf_sample"])
plain=C.a5_decrypt(mt["a5"], mt["a1"], int(mt["a3"]), int(mt["a4"]), k2)
print(json.dumps(json.loads(plain), ensure_ascii=False, indent=2))
PY
```

- 解密器:`mtgsig/mtg_crypto.py`(`a5_decrypt` / `A9Cipher`)。
- keeta 常量:`mtgsig/keeta_const.json`(k2buf/salt/embeddedA0)。
- 国内全局 salt(对照):`84196261031a0c3557301d0dda77b59d`(`ref_domestic/k2buf.go`)。
- 样本:`/tmp/keeta_K.json`(真机 mtgsig)、`mtgsig_app（国内）/mtgsig_go/example_request.json`(国内)。
