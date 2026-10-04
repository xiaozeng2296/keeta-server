# 登录 B 指纹：字段来源与已有观测复用

> 历史研究资料，来源 `codex/keeta-project@6197c528`；保留当时的观测与未完成项，不代表新项目当前状态。当前规则见 [字段状态](../MTGSIG_FIELDS_STATUS.md)，复跑入口及已修正结论见 [离线研究指南](../research/OFFLINE_RESEARCH.md)。文中的旧 `dump/`、抓包及设备路径仅作证据索引，原材料未随仓库发布。

适用已分析的 Keeta iOS 3.12.401 二进制。本文结论来自静态引用和现有观测，
没有启动手机采集或发送业务请求；能够构造指纹不等于 risk 接口放行。

`-[SAKWindFingerprintGenerator requestSyncCorpse]`（RVA `0x2846944`）先收集语义字典，
再调用 `n6FlSj8h:` 转换字段名，最后由 `d5fB4mkd:` 执行 JSON/AES/Base64。
`0x28474d4` 初始化全部 45 项映射，`0x2847484` 执行逐键转换。
因此下面的名称不是根据样本外观猜测。

| 字段 | 原生语义键 | 含义 |
|---|---|---|
| I1 | utm_medium | 设备类别 |
| I2 | dtk_token | 推送令牌配置 |
| I3 | root | 越狱检测结果 |
| I4 | net | 网络类型 |
| I5 | app_dection | 应用检测结果 |
| I6 | mno | 运营商名称 |
| I7 | batteryLevel | 电池百分比 |
| I8 | dm | 设备型号 |
| I9 | batteryState | 电池状态 |
| I10 | os | 操作系统版本 |
| I11 | cell | 运营商信息 |
| I12 | sc | 屏幕像素尺寸 |
| I13 | systemVolume | 系统音量采集值 |
| I14 | bootTime | 内核启动时间，秒 |
| I15 | wifimac | Wi-Fi 信息 |
| I16 | gyro | 陀螺仪采集数组 |
| I17 | location | 位置对象 |
| I18 | idfa | IDFA，广告标识 |
| I19 | firstlaunchtime | 此 SDK 持久化的首次启动时间 |
| I20 | idfv | IDFV，供应商标识 |
| I21 | locstatus | 定位授权状态 |
| I22 | simstate | SIM 状态 |
| I23 | storage | 可用／总存储，MiB |
| I24 | phonename | 设备类型名称 |
| I25 | wifiip | 网卡 IP，可以是 IPv4 或 IPv6 |
| I26 | source | 安装来源 |
| I27 | business | 指纹生成器业务配置 |
| I28 | dpid | 指纹生成器 dpid 配置；不自动等同 a8 |
| I29 | app_version | App 版本 |
| I30 | finger_version | 指纹格式版本 |
| I31 | magic | SDK magic 常量 |
| I32 | ch | 渠道配置 |
| I33 | dylibs | 加载动态库列表 |
| I34 | coreFileCreateTime | CoreServices 路径创建时间 |
| I35 | coreFileModifyTime | CoreServices 路径修改时间 |
| I36 | phonenameInFile | 系统配置文件中的设备名 |
| I37 | installtime | App 安装时间，毫秒 |
| I38 | brand | 厂商 |
| I39 | local_time | 当前墙钟时间，毫秒 |
| I40 | uuid | OneID csecuuid；与本次身份绑定 |
| I41 | memory | App 驻留内存／设备总物理内存，MiB |
| I42 | scBrightness | 屏幕亮度 |
| I43 | cpuCore | CPU 核数，JSON 数字 |
| I44 | cpuUsage | App 非 idle 线程 CPU 使用率之和，百分比 |
| I45 | cpuStyle | CPU 架构 |

## 当前 m 观测的确证转换

m 采集分发器 `0x34eaa4` 的编号表为 `0x350e14`（字段 1–30）和
`0x350e8c`（字段 122–460）。按表定位对应 getter 后，可确认：

| B 字段 | 已有观测转换 | 静态依据 |
|---|---|---|
| I14 | `floor(m149 / 1000)` | 两路 `sysctl({1,21})`；B 取 `tv_sec`，m 取毫秒 |
| I23 | `%.6f(m131/2^20) @ %.6f(m132/2^20)` | 两路使用 `cipf_fileSystemFreeCapacity/totalStorageCapacity` |
| I36 | `m5` | 两路读取同一 preferences.plist 的 `System/System/ComputerName` |
| I41 | `%.6f(m6/2^20) @ %.6f(m157/2^20)` | 两路使用 `task_info` 的 resident_size 与 `physicalMemory` |
| I42 | `%.5f(m142)` | 两路使用 `UIScreen.mainScreen.brightness` |
| I43 | `int(m139)` | 两路使用 `NSProcessInfo.processorCount` |
| I44 | `%.5f(m135 * m139)` | m135 是线程 CPU 使用率总和除核数，原格式 `%.6f` |
| I45 | `m140` | 两路使用 `NXGetLocalArchInfo` |

旧文档中的 m6“构建号”、m135“温度／磁盘比例”、m142“电池电量”均不符合这些 getter。
I41 的第一个数是 App RSS，不是系统剩余内存。

I41 的 B getter 为 `0x284988c`，m6 getter 为 `0x34aa3c`，m157 getter 为 `0x34ab2c`。
I44 的 B getter 为 `0x2848224`，m135 经 `0x34b1b0 → 0x34afdc`。
两路 CPU 计算均调用 `task_threads/thread_info(THREAD_BASIC_INFO)`，
过滤 `TH_FLAGS_IDLE`，累加 `cpu_usage / 1000 * 100`；m 路另除核数。

`m135` 保留六位小数，乘核数并不能恢复丢失的尾数。N 核时，反推 CPU 百分比的
原序列化误差不超过 `N × 0.0000005` 个百分点；最终五位格式另有至多
`0.000005` 个百分点的舍入。本次 6 核快照的前者为 `0.000003`，整个误差区间
格式化到五位小数相同。此检查不表示独立时刻的 B 原生采样会逐字相等。

## 时间、缓存和最小边界

I39 在 `0x28484b0` 取 `NSDate.timeIntervalSince1970 × 1000`，通过 NSNumber 的
`%@` 描述输出，可含毫秒小数。它可以在协议构造时获得，无需额外手机采样。
现有构造器默认整数毫秒；需要保留明确的浮点文本时，使用显式动态字段覆盖。

B 的 I23 在 `dispatch_once` 内采样并缓存，I41/I44 每次采集读取进程状态。
使用已有 m 数据构造的是**明确选定的观测快照**，不能称作当前 B 缓存的原样重现。
协议构造无需为了这两项无限重采样。

两个不能直接拿近似 m 字段替代的持久时间：

- **I19** 读取 `CIPStorageCenter(sec)` 的 `com.jpm.firstlaunchtime`；m148 读取
  `com.dfp.firstlaunchtime`，键不同。即使都是首次启动时间，也不能互相替换。
- **I37** 来自 `cipf_appInstallTime` 的 NSNumber 毫秒描述。m155 虽使用相同 API，
  随后经 `floatValue → %.0f` 丢失精度，不能精确逆推 I37。尤其不能把 m149 开机时间
  或 m311 构建戳填成安装时间。

若目标是还原当前原生 B 的确切字节，I19 的对应持久值、I37 的原始 NSDate 精度仍需
当前来源；若目标是明确标注来源的协议快照，可保留已有观测并声明它们的时点。
其他未更新的历史字段也在私有报告中逐项列明，没有将其重新标为本次测量。

## 工件与验证

`dump/registration_session/login_prepared_02/profile-extension.json` 提供完整
`fingerprint_obj` 和当时尚未恢复的空 `token_id`。后续实测确认空 token_id 导致参数错误，
当前登录上下文已补齐 App 固定配置，详见 `EMAIL_TRIALS.md`；不要再把该空值当作完整登录配置。
已更新上述八个观测字段、
I39 快照时间，以及当前身份 I18/I20/I40；I19/I37 的历史值保留并标记。

同目录 `validation.json` 记录创建时间、源文件 SHA256/mtime、源 SDK 时间与 m150，
以及量化边界；`native-key-map.json` 与 `confirmed-name-map.json` 包含全部 45 项名称。
`login_prepared_01/b_static/` 保存映射表、getter、编号分发表和展开汇编。
新输入已经过生产 `prepare_request_profile` 与 AES 解回验证，45 个字段完整。
没有构造含邮箱的可发送请求，没有发送 confirm/risk/apply，没有改运行代码。
