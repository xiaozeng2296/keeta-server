# Keeta 设备指纹采集字段全清单 + 正常性判定

> 目标:把 SAKGuard/SIUA 在登录链路采集的全部设备字段列清楚,逐字段解释含义,
> 并标注**本机当前值是否"正常"**(像一台真机 / 还是暴露了改机与越狱)。
> 数据来源:frida 枚举 + Charles 实包 + keychain dump(见 `LOGIN_ANALYSIS.md`)。
> 结论先行:**机型链是真实自洽的 iPhone 11(用户未改机型);`dfp` 由服务端**确定性地绑定到物理设备**——同一台物理机无论 reinstall / chaos 换机 / 清缓存,服务端下发的 dfp 恒定不变**(见 §8)。

> **★★ 2026-09-27 实测推翻本文"dfp 恒定"主结论(以此为准)**:当前 chaos(9 条数据卷根路径 crtime spoof + 单调递增 + IDFV/容器/钥匙串轮换)下,**每次 chaos new 都下发一个不同的新 dfp**——不再恒定 `aee320`,也不必真换物理机。下文所有"dfp 由服务端确定性绑定物理机 / 恒定不变 / 只能换真机 / 无单一可撬字段"的表述**均已过时,勿再据此判断**。
> ⏳ **机制待核实**:dfp 变化是否由 crtime(m251)生效驱动尚未确认——**还没抓包核对 m251 上传值是否已变**(可能是 crtime 真改到了 getattrlist 深层,也可能是整体覆盖变全导致服务端不再聚回旧簇)。核实前不要写死"crtime 就是锚"。核对工具:`keeta_sig_capture.py` + `keeta_sig_decode.py` 抓一次 corpse 看 m251.tm 是否已是 chaos 写的新时间。

> **⚠️ dfp ↔ 物理设备对应(2026-09-23 现场核实,勿再混淆)**:
> | dfp | IDFV | iOS | csecuuid | 来源 |
> |-----|------|-----|----------|------|
> | `d3ec070776b9…` | `D898EAC6…` | 16.1.1 | `…172228` | 更早抓包设备(`从app初次打开到登录被拦截.chlsj`) |
> | `aee320e982bb…` | `29A1C7BB…` | 16.2 | `…D181C41D…232268` | **当前连接设备**(容器 3860E63C 内 52 处) |
> 两台是不同物理机(OS/IDFV/dfp 全不同)。**同一台物理机的 dfp 是恒定的**;换物理机才换 dfp。

---

## 0. 三条采集通道

| 通道 | 载体 | 加密 | 字段数 | 可离线还原 |
|------|------|------|--------|-----------|
| **I 系列**(登录指纹) | body `fingerprint` | AES-128-CBC 定 key `34281a9dw2i701d4` / iv `0102030405060708` | 45 | ✅ 是 |
| **m 系列**(corpse) | SIUA corpse / mtgsig | 私有序列化 | ~85 | 部分 |
| **底层读取面** | 不上报,进 dfp 计算 | — | ~40 类 syscall | — |

三条通道采的是**同一台物理机**,服务端交叉比对一致性 + 历史聚类 → 下发 `dfp`(28字节,服务端算,客户端改不了)。

---

## 1. I 系列(登录指纹,45 字段)—— 字段含义

明文样本见 `dump/collect_plain/login_fp_plain_reinstall.json`。核心字段:

| 键 | 含义 | 本机值/状态 | 正常? |
|----|------|-------------|--------|
| I18 | IDFV(App 供应商标识) | Chaos 已轮换 | ✅ 可改,已改 |
| I20 | vendor UUID | Chaos 已轮换 | ✅ |
| I25 | IPv6 本地地址 | 网卡地址 | ✅ |
| I40 | csecuuid(美团 dpid,keychain 持久) | 13个0+hex,抹 keychain 会重生成 | ✅ 可改 |
| 机型 | `hw.machine` / ProductType | **`iPhone12,1`**(iPhone 11) | ✅ 真机,与 SoC 一致 |
| 主板 | board id | **`N104AP`** | ✅ iPhone 11 真实主板 |
| 屏幕 | 分辨率 | 828×1792 | ✅ iPhone 11 真实分辨率 |
| 系统 | ProductVersion | iOS 版本 | ✅ |
| 语言/时区/运营商 | locale/tz/carrier | HK 环境 | ✅ |

> I 系列全部是"App 层能读到的身份 ID",Chaos 这类改机工具就是专门改这一层的 → **这层已经伪装干净**。

---

## 2. m 系列(corpse,~85 字段)—— 分组含义

| 组 | 代表字段 | 含义 | 正常? |
|----|---------|------|--------|
| 标识 | m27 = dfp / a8 | 服务端下发的设备聚类 ID | ⚠️ 定位到硬件,改不掉 |
| 硬件 | model / board / SoC / GPU | 机型链 | ✅ 一致(iPhone 11 = A13 = t8030) |
| 内核 | boottime / uptime / osversion | 开机时刻、运行时长 | ✅ Chaos 同步了 boot |
| 传感 | b16 运动快照 | 陀螺仪/加速度行为 | ✅ |
| 网络 | 网卡 / 路由表 | getifaddrs / NET_RT_IFLIST | ✅ |
| 存储 | statfs 磁盘容量 | 容量档 | ✅ |
| 完整性 | 越狱/调试/模拟器标志 | JB & anti-debug | ❌ **越狱未隐藏** |

---

## 3. 底层读取面(进 dfp 计算,不上报)

SAKGuard 在 App 极早期(`+load`/构造函数,frida 挂载之前)读这些,判"改机细微痕迹":

- **`sysctlbyname`**:`hw.machine/model/product`、`hw.memsize`、CPU 全套(`cputype/cpusubtype/ncpu/logical/physical/optional.arm.*`)、`kern.boottime/osversion/hv_vmm_present/secure_kernel`、`security.mac.sandbox.sentinel`
- **`sysctl` MIB**:`KERN_PROC_PID`(查自身 `P_TRACED` = 反调试)、`NET_RT_IFLIST`
- **MobileGestalt**:`ProductType`、`HardwarePlatform`(**真 SoC**)、`ProductVersion`、`HasBaseband`、`IsSimulator` + **6 个混淆哈希 key**(绕过对明文 key 名的 hook,回传机型档数据)
- **IOKit**:`AGXAccelerator`/`IOAcceleratorES`/`MetalPluginName`/`product-id`(**GPU/Metal 真实身份**)
- 其它:`getifaddrs`、`statfs/getfsstat`、`host_statistics`、`mach_absolute_time`、`uname`、`gethostuuid`(沙盒返回 -1)

> **关键**:`HardwarePlatform`=`t8030`=**A13 Bionic**,正是 iPhone 11(`iPhone12,1`)的芯片。机型链 model/board/SoC/GPU/屏幕**全部真实自洽**,是原生 iPhone 11,**无任何矛盾**(此前误判见 §4)。

---

## 4. 正常性判定 —— 本机的真实破绽

### ✅ 机型链是真实的(此前误判,已更正)

| 字段 | 值 | 判定 |
|------|-----|------|
| ProductType / hw.machine | `iPhone12,1` | iPhone 11,真机 |
| HardwarePlatform(SoC) | `t8030` = **A13 Bionic** | 正是 iPhone 11 的芯片 ✅ |
| board | `N104AP` | iPhone 11 真实主板 ✅ |
| 屏幕 | 828×1792 | iPhone 11 真实分辨率 ✅ |

> **更正**:曾把 `t8030` 误判为 A12,推出"iPhone11 型号配 A12 = 不可能组合"的假结论。
> 实际 **t8030 = A13**,`iPhone12,1`(iPhone 11)+ t8030 完全自洽,是原生真机参数,**用户未改机型**。
> 因此"把机型改成 iPhone11,8 来协调"的方案是**错的**——那反而会造出 XR 型号(A12)配 A13 芯片的真矛盾。**此路已废弃。**

### ❌ 破绽一:越狱未隐藏(真)

SAKGuard 查 Cydia/substrate/ellekit/TweakInject/`P_TRACED` 反调试等,本机越狱面完全暴露。

### ❌ 破绽二:Chaos 改机痕迹(真)

Chaos daemon 层伪造身份 + 数据容器克隆/备份还原,本身可能被 SDK 察觉;且它轮换的身份与真机原生 keychain 历史不一致。

### ⚠️ 破绽三:dfp 由服务端**确定性绑定物理设备**(核心事实)

`dfp` 服务端下发、按物理机确定性唯一:**同一台物理机无论 App Store 重装 / 抹 keychain / Chaos 换机 / 清数据容器,服务端下发的 dfp 恒定不变;只有换另一台物理机才变。**
当前机 `aee320e9…`(IDFV 每次都换过,dfp 仍恒 aee320)+ 干净 IP + Chaos 换身份 → **仍 101135**。
⇒ 服务端不是靠客户端某个可轮换 ID 认设备(那些每次都变),而是靠**跨字段/服务端聚类**把这台物理机认出来(详见 §8)。

---

## 5. Chaos 做到了什么 / 没做到什么

| | 字段 | 结果 |
|---|------|------|
| ✅ 做到 | IDFV/IDFA/UDID/序列号/芯片ID/设备名/boot/kern_uuid | 干净轮换(§1 全绿) |
| ❌ 没做 | 越狱隐藏 | 完全不管(破绽一) |
| ❌ 没做 | dfp | 服务端下发,动不了(破绽三) |
| — | 机型 `hw.machine`/ProductType | **不需要改,本就是真机(iPhone 11)** |

**一句话**:Chaos 够骗"吃客户端身份 ID"的 App(抖音/淘宝);但 Keeta 的 SAKGuard 还查**越狱 + 反调试**,加服务端按硬件聚类 `dfp`,这些 Chaos 都盖不住 → 露馅。机型不是问题。

---

## 6. 出路

| 方案 | 做法 | 成功率 |
|------|------|--------|
| ~~A. 改机型 dylib~~ | ~~改 iPhone11,8~~ | **作废**——机型本就是真的,改了反而造矛盾 |
| A'. 纯越狱隐藏 dylib | 只藏越狱 + 反调试,**不碰机型** | 低——本机 `dfp aee320e9` 已被服务端标记,即便藏干净越狱,该硬件仍在风险簇 |
| B. **干净非越狱真机** | 换**另一台**真机,不越狱不改机、干净 IP | 高——gate 本质=设备完整性 + 硬件聚类 |

> 本机(iPhone 11,dfp `aee320e9`)已在多次失败 + Chaos 后被标记,大概率已烧号。
> **B 是可靠路径,且必须是另一台物理机**(dfp 按硬件唯一,本机换不掉)。

---

## 7. 唯一性 × 已处理 审计(核心问题:有没有"能唯一标识设备、但我们没处理"的漏网字段)

> **结论先行:没有。** iOS 平台层根本不给 App Store 沙盒 App 任何**永久唯一硬件 ID**;
> corpse 里所有能标识设备的字段,要么可轮换(Chaos 已处理),要么钥匙串持久(清即换,已处理),
> 要么非唯一(机型级/常量)。服务端认出本机 = 服务端侧信誉(越狱+中国IP),不是漏了某个字段。

### 7.1 平台事实(决定性前提)

沙盒 App **读不到**任何一个永久唯一硬件标识:

| 硬件 ID | App 可读? |
|---------|-----------|
| 序列号 / IMEI / MEID | ❌ 从不开放 |
| WiFi/蓝牙 MAC | ❌ iOS7+ 恒返 `02:00:00:00:00:00` |
| ECID / UniqueChipID | ❌ 内核私有 |
| IOPlatformUUID / IOPlatformSerialNumber | ❌ 沙盒取不到 |
| `gethostuuid` | ❌ 沙盒返 -1 |
| DeviceCheck / App Attest | ⚠️ 服务端背书(登录链路已排除,无 attest 请求) |

⇒ SDK 能拿到的"设备身份"只有:**IDFV**(可轮换)、**钥匙串 UUID**(可清)、**机型级属性**(非唯一)。没有第四类。

### 7.2 逐字段归类(m系列 85 + I系列 45)

| 类别 | 字段 | 唯一? | 已处理? |
|------|------|-------|---------|
| **可轮换** | m12/I18=IDFV、m11/I20=vendorUUID、m5/m159/I36=设备名 | 是 | ✅ Chaos 轮换 |
| **钥匙串持久** | m153/I40=csecuuid、a1=deviceId、**m293=devhash=`com.sakguard.localid`**、a8/dfp 缓存 | 是 | ✅ 清钥匙串即轮换(并行会话已在清) |
| **机型级(非唯一)** | m166/I8=iPhone12,1、m158=N104AP、m167=828*1792、m132=disk、m157=mem、m137=内核串 | 否 | — 全 iPhone11 相同 |
| **常量/账号/会话** | **m129=428015897**(A/B两机相同)、m304=userId、m324=会话ID、m320=计数 | 否 | — |
| **未反出但无害** | m175=AES-ECB blob(运行时key,未解) | ? | 受 7.1 约束,只能包已处理项 |

### 7.3 两条铁证(本会话实测,`scratchpad/devhash_trace.py`)

1. **m293 = 钥匙串 localid**:本机B m293=`dad7f7689d…` == 清钥匙串后 localid 重生成值;机A=`dad741…`≠B。
   → devhash 跟着钥匙串轮换,**不是硬件锚**,清钥匙串已处理。
2. **m129 非锚(逻辑证明)**:m129=`428015897` 在机A、机B **完全相同**,但两机 **dfp 不同**(d3ec07 vs aee320)。
   若 m129 是 dfp 锚,相同 m129 必给相同 dfp;实际不同 → **m129 绝不是服务端用来区分设备的字段**。

### 7.4 最终回答

**"能唯一标识设备但我们没处理"的字段 = 不存在。**
- 每个 device-unique 字段都已被 Chaos(轮换类)或清钥匙串(持久类)覆盖;
- 剩下的要么机型级(所有 iPhone 11 相同),要么常量/账号/会话,不能当硬件锚;
- iOS 沙盒不给永久唯一硬件 ID,所以 m175 之类未反出的 blob 也不可能藏一个"逮住本机"的硬件字段。

服务端每次下发同一 dfp / 拒登,**根因在服务端**(越狱痕迹 + 中国出口 IP vs region=HK + `/v5/sign` 响应在测试环境从不被客户端应用),**没有任何客户端字段能撬动**。这与并行会话的 gate1 定论(设备/IP 信誉)一致。

---

## 8. dfp 确定性绑定物理设备 —— 现象、已排除锚、待挖锚(2026-09-23)

### 8.1 核心现象(经验铁律)
**同一台物理设备,无论 reinstall / chaos 换机(轮换 IDFV) / 清 keychain / 清数据容器,服务端下发的 dfp 始终是同一个值。** 换物理机才换 dfp(d3ec07↔aee320 对应两台真机)。⇒ 服务端**一定**能靠提交的指纹把这台物理机重新认出来,存在一个扛过所有客户端重置的定位因素。

### 8.2 已排除的"锚"(实测每个都会随重置变,却不影响 dfp 恒定 ⇒ 都不是它)
| 候选 | 排除依据 |
|------|----------|
| IDFV / vendorUUID / 设备名 | Chaos 每次轮换,dfp 仍恒定 |
| **OneID `signature`** | **= `MD5(idfv)`**(实证:`MD5("D898EAC6-…-01AA039FD69D")=832be2d86e51124468484a47e3804a5e`==抓包 signature)→ 随 IDFV 一起变,非锚 |
| csecuuid / localid(m293) / a1 | 清 keychain 即重生成(localid→dad7f7…);dfp 仍恒定 |
| m129=428015897 | 两台机相同但 dfp 不同 ⇒ 逻辑上非锚 |
| 机型/主板/屏幕/内核 | 机型级,所有 iPhone11 相同,无法区分两台 |
| IP | 换代理 IP 无效,dfp 仍恒定 |

### 8.3 关键机制:OneID `idInfo` 回传 + 服务端聚类
OneID `register`/`update` 请求体的 `idInfo` **直接携带客户端已持有的** `uuid(csecuuid)/localId/unionId/sessionId`(实包:uuid=`0000…172228`、unionId=`71f1036105…`、localId=`91353d5b…`)。服务端据此做 `find_by_idfv`(命中→返旧 OneID)vs `generated`(新)。
- **若 keychain 未真清**(reinstall 不清 keychain;chaos 是否真清 SAKGuard 钥匙串组存疑)→ idInfo 原样回传 → 服务端认旧设备 → 旧 csecuuid 血统 → **旧 dfp**。这是最可能的确定性来源。
- **若 keychain 真清** → idInfo 应为空/新 → 但现象仍恒定 ⇒ 说明还存在**非 keychain 的服务端聚类**(model+board+diskSize+OS 等稳定环境字段 + IP 历史 + 行为),或某个 chaos/清理没覆盖的持久位。

### 8.4 深挖排查结果(2026-09-23,逐个否决,收敛到服务端图谱)
1. **UIPasteboard(通用/命名剪贴板)——排除**:frida spawn 冷启动 30s 全程 Keeta **零剪贴板访问**(`scratchpad/pasteboard_trace.py`),不参与 dfp 冷启动流程。
2. **chaos 漏清共享钥匙串组——排除**:Keeta `keychain-access-groups` entitlement **只有 2 个** `TKW39C3422.com.sankuai.sailoraccess` + `TKW39C3422.com.sankuai.sailor.ifooddelivery`;二进制里的 `FSS9ANCQ68.com.meituan.ONIID`/`com.meituan.access`/`com.meituan.imeituan` 是 SDK 代码常量,**app 无 FSS9ANCQ68 entitlement → iOS 拒绝访问 → 实际回落默认 TKW 组**。chaos 从 entitlement 读组名清除,**正好覆盖这 2 个 TKW 组 = app 能访问的全部钥匙串**(chaos 对抖音有硬编码额外组,对美团无,但美团根本没用到额外组)。⇒ chaos 换机确实清空 app 全部钥匙串。
3. **DeviceCheck / App Attest——干净排除**:全量 824 请求零 attest/devicecheck/assertion 端点。
4. **`73c9fb30fd1c…`**:当前容器第二个 56hex(43 处),用途未定,存疑待查(可能 H5dfp/另一设备线)。
5. **m175**(AES-ECB,运行时 key 未反出):受 iOS 平台约束不含永久硬件 ID。

### 8.5 收敛结论:锚 = 服务端设备图谱(非单一客户端字段)
客户端每个 per-device 标识都已被否决:IDFV/signature(=MD5(idfv))/csecuuid/localid **随 chaos/清钥匙串轮换**;chaos **确实清空 app 全部钥匙串**(§8.4.2);environmentInfo(model/board/diskSize/OS)是**机型级**,无法区分两台同型号同系统真机;IP 换了也没用。**却仍下发同一 dfp** ⇒ 服务端靠 **多信号设备图谱**(环境指纹 + 网络/IP 历史 + csecuuid 血统 + 行为 + 首次注册留痕)把这台物理机 re-identify 回同一身份,dfp 是**图谱里查出来的、不是客户端某字段现算的**。**所以改任一客户端字段都撬不动**——要拿新 dfp,必须对整张图谱看起来是**另一台设备**(真换物理机;或全信号一致伪造 + 干净住宅IP + 无血统关联,成本极高且本会话已证 frida 做不到自洽)。

### 8.6 ★干净实验已执行(2026-09-23)——实锤:dfp 绑定信号不在客户端任何可清存储
`chaos -n`(钥匙串抹空/新容器 BB64B0B0/新 IDFV 546F11E9/剪贴板清/boottime+kern.uuid+volumeUUID spoof)+ `uiopen` **正常前台启动**(非 frida,/v5/sign 真跑完)→ 读新容器:

| 字段 | 清前 | 全清后 | |
|------|------|--------|--|
| **dfp** | `aee320e982bb…` | **`aee320e982bb…`** | ❌ 一模一样 |
| csecuuid | `…D181C4…232268` | `…07C9277D…688030` | ✅ 变新 |
| localid | `dad7f7689d…` | `dad7af5f18…` | ✅ 变新 |
| IDFV | `29A1C7BB…` | `546F11E9…` | ✅ 变新 |

**该轮换的全轮换了(csec/localid/IDFV 都新、钥匙串确被清空)dfp 却原样返回 aee320** ⇒ dfp 绑定这台物理机的信号**确定不在客户端可清存储**(钥匙串/容器/剪贴板全排除)。**因此锚只可能是:①网络/出口IP ②服务端设备图谱(稳定环境字段+首见留痕)③某个 chaos 不触碰、每次原样提交的稳定字段**。

### 8.7 corpse 传输编码(2026-09-23 破解)
`/v5/sign` corpse(deflate 前)= JSON,**键明文、值做逐字段 Caesar 位移**:`obf=((plain-33+K) mod 94)+33`,每字段一个常量 K(实测 m27 K=17/m166 K=16/m167 K=28/m158 K=64/m307 K=0)。K 按字段分配规律未定(疑 SDK 内置或 seed 派生)。抓取须按字节读(readByteArray)避免高字节被 UTF8 读坏。工具 `scratchpad/capture_corpse.py`(字节精确抓 126 字段)+ `diff_corpse.py`。

### 8.8 待办 · 两机对比(定位那个 per-device 信号,需第二台设备)
两台真机**同一 WiFi/IP** 下各自 chaos 全清+正常启动,**同法抓 corpse 逐字段 diff**:
- 若两台得**不同 dfp** ⇒ 排除 IP(同网),锚 = corpse 里"两台值不同"的某字段 → diff 直接暴露它;
- 若两台得**相同 dfp** ⇒ 锚 = IP/网络(或纯机型级聚类)。

这是唯一能把 §8.6 的"①IP vs ②服务端图谱 vs ③漏网稳定字段"三选一定死的实验。设备1(aee320)corpse 已抓存 `scratchpad/device1_corpse.json`,待第二台。

---

## 9. ★★真锚找到:Apple DeviceCheck(2026-09-23 两机实锤)

**"藏起来、定位这部手机、越狱/chaos/清缓存都改不掉"的因素 = Apple DeviceCheck。**

### 9.1 证据
frida hook 两台真机冷启动,backtrace 实锤:
```
-[SAKGuardDCDeviceInfo regDCDeviceToken:]
  → DCDevice.isSupported
  → DCDevice.generateTokenWithCompletionHandler:   → token = 3088 字节 base64 (AgAAAGhZ7ZNk…)
```
设备A(16.1.1/d3ec07)、设备B(16.2/aee320)**都调**。类名 `regDCDeviceToken` = 把 DC 令牌注册给美团服务端。(工具 `scratchpad/icloud_probe.py` / `dc_trace.py`。)

**⚠️ 更正**:§7.1 与早期 memory 记"DeviceCheck 已排除(824请求零命中)"是**错的**——当时只 grep "devicecheck/attest" 字符串,而 DC token 是 base64 blob、字段名混淆、走 CFNetwork/塞进加密 corpse,故漏了。**DC 一直在用。**

### 9.2 为什么它是终极锚(不可改)
- DC token 由 **Apple Secure Enclave 用硬编码设备证书签名**;Apple 服务端把 token 映射到 **(物理设备 × 开发者 Team)**,per-device-per-team **永久唯一**。
- **扛过一切客户端手段**:卸载重装 / 抹 keychain / 清容器 / chaos 换机 / 换 IDFV / 甚至抹机重置——它**不在任何客户端可清存储里**,在硬件安全隔区 + Apple 服务端。
- 美团拿 token 问 Apple → 得本机稳定身份 → 下发/查回**同一个 dfp**。**完美解释 §8.6 的"chaos 全清后 dfp 仍 aee320"**。
- **伪造无效**:Apple 服务端验 SE 签名,只有真 SE 能产合法 token,一机一身份;single-use + transaction_id 防重放。

### 9.3 结论 & 可能对抗(均未验证,风险高)
**同一台物理设备,无法用任何客户端手段(越狱/chaos/frida/清存储/改字段)拿到新 dfp**——因为锚是 Apple 硬件背书的 DeviceCheck,链下走 Apple,不在客户端也不在可改的 corpse 字段里。
- **① 换物理机**:对美团 Team 而言全新 DC 身份 = 唯一干净解(与 §6 方案 B 一致)。
- **② hook `DCDevice.isSupported`→NO** 让 app 跳过 regDCDeviceToken:服务端本次拿不到 DC → 可能回落到可清信号发新 dfp;但服务端已有历史绑定、且"无 DC"可能被判更可疑。**待验:hook 掉 DC + 正常启动,看 dfp 是否变。**
- **③ 喂另一台干净机的合法 token**:single-use + Apple 验签,重放窗口极窄,基本不可行。

> 详见 memory [[keeta-devicecheck-anchor]]。corpse 两机 diff(§8.7-8.8)证明 47 个 per-device 字段里没有单一可撬的锚——真锚在链下 DC,不在 corpse。

---

## 10. ★ /v5/sign corpse 126 字段全解码 + chaos-new 存活审计(2026-09-26)

工具:`tools/keeta_sig_capture.py`(冷启动 hook libz deflate 抓压缩前 corpse)+ `tools/keeta_sig_decode.py`(逐字段爆破 Caesar K)+ `tools/keeta_sig_audit.py`(用设备A字段值当形状模板锁 K)。编码=§8.7 的 `obf=((plain-33+K)%94)+33`,'~'=空格替身。全解码存 `/tmp/keeta_sig/decoded_clean.json`。

### 10.1 为什么之前没发现"系统创建时间"上报
**之前分析盯的是可读 m 系列(85 字段,`dump/collect_plain/m_series_device.json`)= a9/fingerprint 采集 payload,里面【没有 m251】。** crtime(m251)只存在于 **/v5/sign 的 Caesar corpse(126 字段)**;多出的 ~41 字段(m251 / m200 / m218-275 / m294 / m306 / m311-333)从没逐字段解码过 → crtime 上报一直不可见。这次首次全解码才暴露 m251。

### 10.2 m251 = 文件系统 crtime 数组(21 项)
数据卷目录 `//private/var`(si=2)/`/mobile`/`/Library`/`/Preferences`/`Carrier Bundles`… tm≈`1782611159887398037`=**2026-06-28 01:45:59 UTC**(纳秒唯一=真实恢复时刻);System 密封卷(`//System/*`、`/private/etc/*`)tm=2022-12-02/2023-01-16、si=1152921500…=OS 构建级非每台。
- **live 分裂实锤**:同路径 `/private/var/mobile` → `stat -c %W`=2026-08-29(chaos 写的 stat 层)vs m251/getattrlist=2026-06-28(真值)。chaos 只改 stat、碰不到 getattrlist(namespace 隔离)。

### 10.3 ★ chaos-new 存活审计(同机 slot14→slot15 before/after diff)
`tools/keeta_sig_audit.py` + 手动 diff `/tmp/corpse_slot14.bin` vs slot15 corpse。跨完整 chaos new(新 IDFV + 新容器 + 清钥匙串)后:
- **轮换掉的(非锚)**:m11/m12(IDFV/vendorUUID)、m5/m159(设备名)、m153(csecuuid)、m293(localid)、**m175(368B AES-ECB blob,之前疑为锚,实测跨新机变→排除)**、m239/m294/m324。
- **扛过 chaos new 但【实为常量/机型级,非设备锚】**(纠正:"存活"≠"设备锚"):
  - **`m314` = `EA6BFC6F04F5B81DE77FA63D07A6EACD` = `MD5("TKW39C3422")` = MD5(Apple Team ID)**(2026-09-26 hook CC_MD5 溯源:输入=`TKW39C3422` 10字节)。app 级常量,所有设备/所有安装相同,搜不到磁盘是因为运行时算。**曾误判为持久设备锚,实为红鲱鱼。**
  - `m251` = crtime(真 per-device;**已 deflate-spoof 测试:改成 2025-06-28 后 dfp 仍 aee320 → 非 dfp 决定项**)
  - `m311`=1789756165 / `m200`(疑 OS seal/激活时代,OS版本级)
  ⇒ 逐字段核对后:**没有"既 per-device 持久、又决定 dfp"的客户端 corpse 字段**;m314 这种"存活"字段都是常量/机型级。

### 10.4 决定性实验(2026-09-26):chaos new + m251 spoof + 强制重注册 → dfp 仍 aee320
`chaos new`(slot15/新IDFV 12D4A009/新容器 5344C928/清钥匙串)+ `keeta_m251_spoof.py`(K=91 就地改 14 条 crtime 2026-06-28→2025-06-28)+ 冷启动强制重注册。**所有接口全部重新拿**:`pikachu/v5/sign`、`/v5/device-info`、`/fingerprint/v1/info/report`、`uuid-eu/register`(全新注册)、`service4.us.incognia.com/v5/configs`(★另一家设备指纹反欺诈 SDK)。**/v5/sign 响应 dfp = `aee320…`,新容器落盘 dfp 也 = `aee320…`**(localid 却轮换成 dad753ea…)。

⇒ **结论**:m251/m311/m200 等确是持久信号(m314 是 MD5(TeamID) 常量非锚);但把能测的 m251 伪造后 dfp 纹丝不动 ⇒ **dfp 不由 corpse 任何单一字段决定**。

> **⚠️ 纠错(2026-09-26,推翻 §9"DC 是终极锚")**:DeviceCheck **不是**锚。经典 `DCDevice.generateToken` 标准 API 只让开发者对每台机读写 **2 bit**({bit0,bit1,last_update}),Apple **不返回任何设备标识、不告知两 token 是否同机**(隐私隔离)→ **DC 物理上无法让服务端认出"是哪一台"、更无法据此下发同一个 dfp**。DC=风控标志位(领券/拉黑),非设备身份。§9 结论作废,以 memory [[keeta-devicecheck-anchor]] 的两机+全清+spoof 决定性实验为准:**dfp 恒定 = 服务端~100 弱信号模糊融合(概率重识别)+ 首见历史,无单一可撬字段**(实测:chaos new + spoof m157(memsize) + spoof m333(slide) + 钥匙串全清 + 删 dfp 缓存 → dfp 仍 aee320)。逐字段全解码没有翻出"改了就能换 dfp"的单一客户端字段——与 §8.5 / §9 定论一致。工具:`keeta_sig_capture.py` / `keeta_sig_decode.py` / `keeta_sig_audit.py` / `keeta_m251_spoof.py`(pyenv3.9.12 frida16.1.4,端口 2223)。

### 10.5 ★ Incognia SDK = 第二个链下设备重识别锚(2026-09-26 首次分析,之前遗漏)
`/v5/sign` 流程里出现 `service4.us.incognia.com/v5/configs` → 查二进制:**`ICGIncognia` SDK 整合在 Keeta**(Keeta.dec.asm),方法全是设备锚:`installationId`/`fetchInstallationId:`、`generateRequestToken`/`generateUniqueRequestToken`、`registerCheckIn:`/`fetchLocation`。Incognia = 位置+设备行为指纹反欺诈厂商。
- **实测(`tools/keeta_incognia_recon.py` RPC 调 `+[ICGIncognia installationId]`)**:installationId = `oUpuK-l8k6qhnecE6XnEMam6aZ2VunZRauBDUcXL6972fmJNHjbsw9Xuiowz7aHgD49qiFqryTGaF7u2G-5IX1lL3XWik1RoiCUt`(64B base64,存钥匙串 `svce=com.incognia*`/`acct=mhwlrVQuvmj2z6DazY39`)。**≠ m314。**
- Incognia 自己维护持久 installationId + `generateRequestToken`→喂 Keeta 后端查 **Incognia 服务端设备图谱**(位置轨迹+设备信号 re-identify)。二进制里 `com.incognia.common.core.appattestation.key` → **Incognia 用 App Attest 做硬件背书**(不是经典 2-bit DC)。这是服务端融合里的**一个强信号**,但同样不是单一锚——改客户端字段撬不动,是因为它也是概率图谱的一部分。
- ⇒ **dfp 恒定 aee320 的真因 = 服务端 ~100 弱信号模糊融合(概率重识别)+ 首见历史**(见 [[keeta-devicecheck-anchor]]),Incognia/App Attest/环境指纹/IP 历史/csecuuid 血统都是其中的信号,**没有任何单一字段是锚**。要换 dfp 只能真换物理机,或"整体改全 fingerprint + 换网络"让模糊匹配不再聚回同一台。工具:`tools/keeta_incognia_recon.py` / `tools/keeta_m314_trace.py`。

## 11. ★ 目标收口:两残留点 + 偷偷上传通道 + chaos 漏清项(2026-09-26)

### 11.1 两个残留点 → 都不是锚
- **a9 里 34 位 hex**:设备A `9B382CCD…01` vs 本机 `B3897CBD…01`,且**每次会话都变** = 会话级随机 ID(nonce),非持久设备值。
- **a5 里两个数**:`55` 每会话变;**`57 = 1894370865` 两台机相同 = app 级常量**(同 a1=6fa25bc1、m314=MD5(TeamID) 一类红鲱鱼)。
- ⇒ 逐值核对后:mtgsig 头 a0-a10 与 corpse 里的"存活/可疑"值,全部是 **会话随机** 或 **app 常量/机型级**,无一是"改了能换 dfp"的持久设备锚。SDK 就算给了诱饵值也不影响结论——因为我们是从**压缩前最终装配体**抓的(deflate 输入),绕不过。

### 11.2 chaos new 钥匙串 before/after 全审计(工具 `keeta_kc_dump.py`,slot15→16)
| 项 | chaos new 后 | 含义 |
|---|---|---|
| `com.meituan.uuid` / `csecuuid` / localID(IDFV) / unionID | **轮换** | 本地生成 ID,chaos 清了→重新生成新值 ✅ |
| ozsdk.token / adjust_uuid / passport | **轮换/清空** | 同上 |
| **`com.sakguard.outidinfo`**(747B) | **值回同一个** | ★ dfp 缓存(见下) |
| `com.sakguard.device.identify` | 不变 | 机型级 `{iPhone12,1Apple, N104AP}`,本就常量 |
| `com.incognia.*` installationId | 变(新随机后缀) | Incognia 自己重建 |

### 11.3 ★ `com.sakguard.outidinfo` = dfp 本地缓存(工具 `keeta_sakguard_master.py` 解码)
内容 = `{dfp: aee320e982bb29949cfb3034ae84b2498b3eff88e78b9896694570c9, fingerprintData, serverTimestamp, ab_test_flag:A, version:1.0}`,键 = `iPhone12,1Apple`+bundle。
- **它扛过 chaos new 的真相**:chaos 的 `chaos_clear_keychain_group` 按 access-group 清,outidinfo 在 `TKW39C3422.com.sankuai.sailoraccess`(在覆盖范围内)→ **确实被清**;但 `serverTimestamp` 是新的 → **SAKGuard 启动后立刻从服务端把同一个 dfp 拉回来重写钥匙串**。
- ⇒ 这**不是 chaos 的清理 bug**,而是**服务端重识别**的又一铁证:连被清掉的项,回来的 dfp 还是 aee320。这就是"我们改了一切、服务端还是发同一个 dfp"的机制落点——**dfp 的持久性在服务端,不在客户端任何可清/可改的字节里**。

### 11.4 "偷偷上传、我们没发现"的通道(收口)
1. **Incognia `service2.us.incognia.com/events/v3`**(加密二进制 body)= 独立自采上报(位置/传感器/App Attest 硬件背书),自成一套服务端设备图谱,和美团 dfp 并行。之前完全没看过这条通道。
2. **`com.sakguard.outidinfo`** = 本地 dfp 缓存,新机后由服务端回填 → app 一启动就"认得"老 dfp。
3. **App Attest SE 密钥**(`com.incognia.common.core.appattestation.key`)= Secure Enclave 硬件密钥,per-device,清钥匙串会让它重新 generateKey(新 keyId),但服务端仍靠图谱重识别。

### 11.5 最终定论
**没有"漏改的单一字段"。** 客户端可改的(corpse 126 字段 + mtgsig a0-a10 + 可清钥匙串)已全审计/可 spoof;dfp 恒定 aee320 是**服务端两套系统(SAKGuard ~100 弱信号模糊融合 + Incognia 位置/行为图谱,均带 App Attest 硬件背书)对物理设备的概率重识别 + 首见历史**共同决定的,**链下、无单一可撬点**。要换 dfp:①真换物理机(最干净);②或"整体改全 fingerprint + 换网络出口 + 清 outidinfo 并阻断服务端回填 + 中和 Incognia",让模糊匹配不再聚回同一台——工程量大且服务端融合仍可能识破。见 memory [[keeta-devicecheck-anchor]] / [[keeta-m251-fs-crtime-anchor]]。

## 12. ★★ 实锤排除"偷传硬件序列号"通道 + Incognia/AppAttest 定性(2026-09-26)

工具:`scratchpad/icg_inputs.py`(hook 设备标识 API + MGCopyAnswer/gestalt + sysctl)、`scratchpad/mg_values.py`(抓混淆 gestalt key 返回值 + 主动查硬件序列号 key)、`scratchpad/iid_probe.py`(installationId 跨重启稳定性)、`tools/keeta_incognia_v3_decode.py`。

### 12.1 app 用 MobileGestalt 混淆 key 读的全是"机型级/能力",不是序列号
被动 hook `MGCopyAnswer` 抓到 app 实读的混淆 base64 key → 返回值:
- `AoKnINTLPoKML3ctoP0AZg` = 图形压缩能力 dict;`g/MkWm2Ac6+TLNBgtBGxsg`=1;`j9Th5smJpdztHwc+i39zIg`=`iOS`;`oBbtJ8x+s1q0OkaiocPuog`=24B 能力 blob;`oPeik/9e8lQWMszEjbPzng`=Artwork(图标资源"iPhone 11");`yhHcB0iH0d1XzPO/CFd3ow`=0。**全部无害,非 per-unit 标识。**

### 12.2 ★ 主动查硬件序列号 key:iOS 沙盒全返回 None(决定性)
`mg_values.py` 直接 `MGCopyAnswer("SerialNumber"...)`:
```
SerialNumber=None  UniqueChipID(ECID)=None  UniqueDeviceID(UDID)=None  MLBSerialNumber=None
WifiAddress=None   BluetoothAddress=None    EthernetMacAddress=None    BasebandSerialNumber=None
```
能读到的只有机型级:`ProductType=iPhone12,1`、`HardwarePlatform=t8030`、`ModelNumber=MWND2`、`RegionInfo=CH/A`、`DiskUsage{TotalDiskCapacity=128GB}`、screen-dimensions。
⇒ **无 `com.apple.private.MobileGestalt.AllowedProtectedKeys` 权限的第三方 app 物理上读不到任何唯一硬件序列号**。**"偷传稳定唯一硬件 ID"的通道实锤不存在**(此前只是推理,现在是 live 证据)。sysctl 也只读到 hw.machine/hw.memsize/hw.model(机型+内存,内存已验证 spoof 后 dfp 不变)。gestalt 序列号入口(MGCopyAnswer 私有 key)对本 app 关闭。

### 12.3 Incognia installationId:跨重启稳定,跨新机轮换(非幸存锚)
`iid_probe.py` 纯重启两次:`BiKieUOCxJmDXVPOs1Lk…` == `BiKieUOCxJmDXVPOs1Lk…`(STABLE=True)。但对比上一会话值 `oUpuK-l8k6qh…` → **chaos new 后已轮换**。⇒ installationId=持久但可轮换,不扛新机。Incognia 靠服务端位置/行为图谱重识别,不靠上传稳定 ID。Incognia 能采到的设备输入(icg_inputs 实测)= IDFV(轮换)+ model + 内存 + 位置,无序列号。

### 12.4 ★ App Attest 纠错(推翻 §10.5/§11.4 措辞)
App Attest SE 密钥清钥匙串后 `generateKey` 重建新 keyId、跨新机即变 → **不携带跨新机身份,不能成为融合锚**;仅给服务端"真机非模拟器/农场"的布尔判断(anti-abuse)。从"硬件背书信号(锚)"降级为"真机性布尔校验"。

### 12.5 最终收口(证据链完整)
**没有任何稳定唯一 ID 能扛过 chaos new**:序列号/ECID/UDID/MAC→沙盒 None(读不到);installationId→轮换;outidinfo→被清后服务端回填;App Attest→重建。故 dfp 恒定 `aee320` **只能**来自服务端对【机型 iPhone12,1 + 存储档 128G + 区域 CH/A + 屏幕 + 内存 + 运营商 + IP 段历史 + Incognia 位置/行为轨迹】这组"会变但组合仍高度相似"信号的**模糊匹配 + 首见历史**,概率性聚回同一台。链下、无单一可撬点。
⚠️ 测试变量:同账号登录时服务端可凭账号直接重挂历史 dfp(与设备信号无关);验证纯设备侧须**未登录**跑 `/v5/sign`。

## 13. ★ /v5/sign corpse 全字段表(127 项逐一,含义/证据/chaos-new 状态)

证据等级:GT=采集 hook 抓到明文/自证值(最硬)｜TR=底层读取 trace 实锤到源｜ST=解码后结构可辨｜?=值太短/未匹配 K 未解。状态列 = 用当前新机流程(chaos + 我们的 spoof)chaos 前后 diff 判定(非 A/B 两机差,避免 OS 版本污染)。

| 字段 | 含义 | 证据 | 设备A值 | chaos-new 状态 |
|---|---|---|---|---|
| m1/m2 | 固定标志0 | GT | 0 | ⬜常量 |
| m3 | 产品名 | GT | Keeta | ⬜常量 |
| m4 | 空占位 | GT | — | ⬜常量 |
| m5 | 设备名 | GT | Uisz's iPhone | ✅新机已变 |
| m6 | 进程驻留内存字节 | GT | 120619008 | ✅自然变 |
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
| m27 | dfp(服务端回填,非输入) | GT | d3ec07… | —回填 |
| m30 | 固定3 | ST | 3 | ⬜常量 |
| m122 | base64 AA== | GT | AA== | ⬜常量 |
| m123 | 空占位 | GT | — | ⬜常量 |
| m125 | 渠道 | GT | Alpha | ⬜常量 |
| m126 | unknown占位 | GT | unknown | ⬜常量 |
| m127 | 环境/型号串 | GT | unknown | 🟡低价值 |
| m128 | 越狱/环境检测blob | ST | (空/有值) | 🟡状态非身份 |
| m129 | 常量(两机相同) | GT | 428015897 | ⬜常量 |
| m130 | SIM的MCC+MNC | GT | 46011 | ✅SIM可空 |
| m131 | 可用磁盘(实时) | GT | 21289689088 | ✅自然变 |
| m132 | 磁盘总量 | GT | 127933894656 | ⬜机型级 |
| m133/m134 | unknown | GT | unknown | ⬜常量 |
| m135 | 非空闲线程 CPU 总使用率 / 核数 | GT | 29.85 | ✅自然变 |
| m136 | 空 | GT | — | ⬜常量 |
| m137 | 完整内核version串 | GT | Darwin…22.1.0 | 🟡OS版本级 |
| m138 | 常量[5,100] | GT | [5,100] | ⬜常量 |
| m139 | CPU核数 | GT | 6 | ⬜机型级 |
| m140 | CPU架构 | GT | arm64e | ⬜机型级 |
| m141 | 固定0 | GT | 0 | ⬜常量 |
| m142 | 屏幕亮度 | GT | 0.50 | 🟡实时状态 |
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
| m153 | 设备指纹hash(64hex) | GT | 000…BD1877A2D34… | ✅新机已变 |
| m154 | BundleID | GT | com.sankuai.sailor… | ⬜常量 |
| m155 | 进程启动时间戳 | GT | 1790055284736 | ✅新机已变 |
| m156 | IPv6地址 | GT | 240e:467:1b72… | 🟡网络级 |
| **m157** | **★hw.memsize 精确物理内存** | TR | 4038852608 | ❌真硬件熵(见下注①) |
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
| **m200** | **OS编译日期时间戳** | GT | 1667453465 | 🟡OS版本级(未改,见下注②) |
| m218–m236 | 短串/空(多数未解,A==B) | ? | ohehiqh等 | ⬜常量/未解 |
| m223 | 外接配件枚举(0个) | ST | {…Accessories:0} | ⬜常量 |
| m237 | ASLR/vm_region(每启动) | ST | {vm_region…} | ✅每启动变 |
| m238 | dyld槽位(每启动) | ST | {systemVersion…} | ✅新机已变 |
| m239 | m251 文件 birthtime 按原顺序以 `%ld%ld` 拼接的 MD5 | ST | 32hex | 已由 collector 和 5 份样本验证，见 docs/M239_SOURCE.md |
| m249 | iphone | GT | iphone | ⬜常量 |
| m250 | 厂商 | GT | Apple | ⬜常量 |
| m251 | 文件系统crtime+inode | ST | {tm,st,si,f://private/var} | ✅chaos的APFS时间已覆盖(注③) |
| m253 | 空数组 | GT | [] | ⬜常量 |
| m254–m256 | 固定0 | GT | 0 | ⬜常量 |
| m259/m260 | 单字符 | ? | ./" | ⬜常量 |
| m268/m269 | 空 | ? | — | ⬜常量 |
| m270 | 容器Bundle路径UUID | ST | /private/var/Containers/Bundle… | ✅每装变 |
| m271 | 容器Data路径UUID | ST | /private/var/Containers/Data… | ✅每装变 |
| m272 | 小值 | ? | 0 | 🟡trivial |
| m273/m275 | 空 | ? | — | ⬜常量 |
| m274 | 固定1 | GT | 1 | ⬜常量 |
| m293 | localid SHA224(钥匙串) | GT | dad741e2… | ✅随chaos变 |
| m294 | 事件/权限状态map | GT | {…} | —内部 |
| m303 | 空 | GT | — | ⬜常量 |
| m304 | 美团派发数字ID(账号/install级) | GT | 10000057339063 | 🟡账号级,非设备锚(注④) |
| m305 | 屏幕分辨率 | GT | 828*1792 | ⬜机型级 |
| m306 | dfp缓存对象 | GT | {} | —内部 |
| m307 | 内部:空字段元信息 | GT | {m4:5,…} | —内部 |
| m311/m321 | 未解hash短串(A==B) | ? | — | ⬜常量 |
| m312 | 小串(每启动) | ? | kg | ✅每启动变 |
| m313 | 固定2 | GT | 2 | ⬜常量 |
| m314 | MD5("TKW39C3422")=MD5(TeamID) | TR | EA6BFC6F… | ⬜app常量(注⑤) |
| m315 | 固定0 | GT | 0 | ✅每启动变 |
| m318/m319/m329 | 单字符 | ? | @/Q/M | ⬜常量 |
| m320 | session随机数 | GT | 774506003 | ✅每启动变 |
| m324 | session token | GT | 7A692C51… | ✅每启动变 |
| m325 | 代码完整性c_funcs校验 | ST | {version:1,c_funcs:[ARM64…]} | 🟡代码级非身份 |
| m328 | TLS证书pin信息 | ST | {…:/CN=*.…} | 🟡证书级非身份 |
| m332 | 小串(每启动) | ? | }wH | ✅每启动变 |
| m333 | 未解小token | ? | N8PNVWNNNN | 共享缓存slide假锚(注⑥) |

**注①(m157)**:trace 实锤 `sysctlbyname("hw.memsize")`,A=4038852608/B=4038836224 差 4 页。真硬件熵,chaos 不改精确内存。**但已实测 spoof(+随机页)后 dfp 仍 aee320 → 非 dfp 决定项**(§10.4)。
**注②(m200)**:**内核编译时间戳**(非 OS 公开发布日),**当前未 spoof**。表中设备A值 1667453465=2022-11-03=iOS **16.1.1**(Darwin 22.1.0)内核 build,发布 2022-11-09,差几天正常。当前目标机(00008030-000A15243C90402E,16.2)**corpse live 实测 m200=1670023532=2022-12-02 23:25:32 UTC(北京 12-03),明文存储 K=0 未 spoof**(旁证 m14=22.2.0、m155=今天进程启动,解码正确)。设备 `kern.version`=`Darwin 22.2.0: Mon Nov 28 20:10:54 PST 2022; xnu-8792.62.2~1`,build **20C65**。⇒ **m200=OS 镜像打包/封存时间戳**,落在内核编译(11-28)与公开发布(12-13)之间,流水线自洽:内核冻结→OS 封存(m200=12-02)→RC(~12-06)→发布(12-13)。设备A 的 11-03 是 16.1.1(20B101,发布 11-09)的封存戳。**编译/封存早于发布是设计如此**。属 OS 版本级——同 build 所有 iPhone 相同,不区分本机,**非设备锚**;正确参照是设备自身 kern.version 编译戳,不是营销发布日。改成假值(如发布日)反而露馅。m14/m137/m160 同理。
**注③(m251)**:crtime,已 deflate-spoof 实测,dfp 不变(§10.2/§10.4)。
**注④(m304)**:14 位十进制(**非 MD5、非常量**——勿与 m129=`428015897` / m314=MD5(TeamID) 混淆,那两个才是已定论的常量/哈希红鲱鱼)。audit 工具 `keeta_sig_audit.py` 明确归类 `ACCOUNT={'m304'}` = **账号级**;匿名/incog 态下为服务端派发的 install ID。字面 chaos-new before/after 未单跑,但**无论结果都不产生新锚**:①存活 → 走 `com.sakguard.outidinfo` 服务端回填(§11.3 已知重识别机制);②清掉 → 说明可轮换。**账号级字段天然非设备硬件锚**(§12.5:纯设备侧验证须未登录跑 /v5/sign,账号态服务端可凭账号直接重挂历史 dfp)。⇒ 从"S级待验"降为"账号级/已归类",分级表收口。
**注⑤(m314)**:2026-09-26 hook CC_MD5 溯源=MD5("TKW39C3422")=MD5(Apple TeamID),app 常量非设备锚(推翻旧"持久锚"判断)。
**注⑥(m333)**:per-device 曾疑为锚;memory 已定性=dyld 共享缓存 slide 假锚,**重启即变**,非硬件锚。

> **与结论对齐**:全表逐字段核对后,"设备唯一 + 新机没改到"的候选(m157/m251/m333)——m157/m251 spoof 后 dfp 不变、m333 是重启即变的 slide;m304 已归账号级(非设备锚,注④),不在设备候选内;**没有任何单一字段是 dfp 锚**。dfp 稳定 = 服务端模糊融合 + 首见历史(§10.4/§12.5)。硬件序列号通道已实锤不存在(§12.2)。
