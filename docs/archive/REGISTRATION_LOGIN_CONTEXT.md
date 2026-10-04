# seq184 后登录请求的最小状态清单

> 历史研究资料，来源 `codex/keeta-project@6197c528`；保留当时的观测与未完成项，不代表新项目当前状态。当前规则见 [字段状态](../MTGSIG_FIELDS_STATUS.md)，复跑入口及已修正结论见 [离线研究指南](../research/OFFLINE_RESEARCH.md)。文中的旧 `dump/`、抓包及设备路径仅作证据索引，原材料未随仓库发布。

本页是 2026-09-28 的只读接续审计，依据本次已接受响应、原新机抓包 627/628 与
`dump/Keeta.dec.asm`。未发送登录请求，未操作手机，也未读取邮箱文件。
已完成的注册、配置和上报不等于登录风控或发码成功。

## 本次可以直接接续的状态

| 输入 | 本次来源 | 用法与边界 |
|---|---|---|
| OneID、DFP、XID、SDK 配置与签名序号 | `dump/registration_session/reporting_live_02/identity-after.json` | 从序号 184 接续；构造下一次签名时递增，不重注册或使用原抓包身份 |
| 设备观测、当前 OneID 与请求输入 | 同目录 `profile-after.json` | 保留 IDFA 与 IDFV 的不同用途；B fingerprint 的设备身份应绑定本次 OneID |
| region/cityId/districtId | `dump/registration_session/region_10_current_local_info/response-01.json` 的 accepted `response.data` | 本次为 HK / 810001 / 8100019；districtId 不是 cityId，也不是任意挑选的城市候选 |
| raw locale/lang/timeZone | 同一 currentLocalInfo 响应 | `zh` / `zh` / `GMT+08:00`；raw 语言应独立保留，不能当成已恢复的 app 当前语言 |
| 区域路由 | 本次 accepted Compass 响应及其 HK 快照 | HK 产品入口为 `fooddelivery.mykeeta.com`，Passport 为 `passport-hk.mykeeta.com`；使用本次明确 `configs` 记录，不宣称已复现 Compass 所有配置层 |
| SDK 区域事件 | seq184 identity/profile | 保留本次 b22/region_events；应用缺失状态不应再补一个虚构历史地区事件 |

seq184 两份文件写出时，profile 仅保存上述区域的扁平字段，未内嵌完整
`region_state`、`compass_snapshot`、`region_compass_response`，也未保存 district_id。
恢复主 flow 时须显式合并此前真实区域工件。不能因为磁盘上存在这些工件，就声称
它们已被 seq184 的执行器自动消费。后续代码已补可选 districtId 的解析和已有 query 回填；
这不会追溯修改旧快照。

## 登录 query 与 header 的最小输入

| 字段 | 已知来源 | 当前可用值或要求 |
|---|---|---|
| appId、package_name、app/SDK 版本 | 当前 app 的明确版本配置 | 本次 appId=517；Passport sdk_version=0.3.63-i18n，不能拿它当 SAK SDK 版本 |
| ci / cityId / region / districtId / timeZone | 当前 accepted 区域状态 | 810001 / 810001 / HK / 8100019 / GMT+08:00 |
| joinkey | `SLHighPriorityLanucher.setupAccount` 固定设置，后被 `SAKBaseModel.getCommonURLParameters:` 消费 | 此版本为 `1101464_49117847`，是 app 配置常量，不是注册响应下发的身份 |
| lang / locale | app 的 `MLocale.currentLocaleIdentifier` | 原新机登录 627/628 观测为 zh-HK；若沿用此 app 选择，须明确记录观测来源，不能标作 currentLocalInfo 自动转换结果 |
| language | 独立系统语言字段 | 原登录请求为 zh-Hans；不能因为 app locale=zh-HK 就一并改成 zh-HK |
| passport_lat / passport_lng | Passport 定位 getter | 原登录请求均为 `0.000000`；是单独的定位输入，不使用 getOpenServiceRegion 的城市中心坐标替代 |
| uuid / csecuuid / pragma-unionid | 本次 OneID 状态 | 按各请求实际存在字段回填，不能沿用旧抓包身份 |
| mtgsig / M-SHARK-TRACEID / __reqTraceID | 本次请求的签名和 trace 构造 | 最终 URL、body、headers 确定后再生成；不可复用旧签名 |
| 其他公共 header | 对应端点模板及当前 app 配置 | 不能把产品接口公共头无差别复制到 Passport |

原 627 confirmProtocol 有 region、locale、uuid 等产品侧 header；原 628 risk 没有这些
header，但有 csecuuid、pragma-unionid、`sailor-net-flag: MTPT.Passport` 及 Passport 公共头。
两者的 query 都有 HK 区域与 zh-HK app 语言。差异应保留，不以统一 header 列表覆盖。

登录 body 还需要：本次明确邮箱、当前 B fingerprint、按当前地区与 app 配置
构造的 tk_context_plain、IDFA 对应的 device_id 和字符串 device_type=`3`。
缺邮箱时停止在发送前；risk 返回真实 userTicket/isSignup 后才能选择 apply 路径。
没有成功 apply 的 data.email/serialNumber，不能报告发码成功。

## 静态消费链与语言边界

已证明的公共参数链：

1. `SLHighPriorityLanucher.setupAccount` 设置 getI18nConfig block；
   block `sub_102284EB4` 返回 `SLCAppI18nInterfaceService.bizCoreParams`。
2. bizCoreParams 的 region/cityId 来自当前 Compass；locale 来自
   `MLocale.currentLocaleIdentifier`；timeZone/districtId 来自 i18nBaseInfo。
3. `SAKBaseModel.getCommonURLParameters:` 独立取 MLocale 写入 lang，
   再合并业务 i18n 公共参数，并添加 appId/cityId/region。

定位链也已明确：`SOAAccountUIConfig.latitude/longitude` → `p_getLocation` →
`CIPPSMRDLocationManager.lastLocation:("iOS-SAKOverseasAccount")` → `marsLocation` →
`coordinate`，分别用 `%f` 输出六位小数。是否携带这两个 query 受
`disableAddLocationInfoOnRequest` 控制。原样本的两个零值是观测，尚未用本次运行状态
证明定位权限/缓存为何为空；不能据零值推导真实地理位置。

语言配置来源链：`getRegionConfigsWithClientType:finished:` 的 callback
`sub_102D96540` 取 response.data → `updateSupportLocalesWithInfo:` →
内存配置与 `SAILORI18N_LOCALE_CONFIG_CACHE_KEY`。读取配置时优先现有内存/缓存，
再尝试 bundle 的 locale_config.json，最后内置默认。内置 HK 列表也为 `[zh-HK,en]`，
所以不能仅凭值相等认定本次 getRegionConfigs 是唯一配置来源。

原生 `defaultLocaleWithRegion:initLocale:scriptCode:` 的匹配顺序已恢复：

- 特判：scriptCode=Hans、区域 HK 且该区域支持列表包含 zh，返回 zh。
- 支持列表包含 initLocale，返回该值。
- 在 localeMappings 组内找受支持的对应语言。
- 用 NSLocale(initLocale).languageCode，按支持列表顺序寻找包含该语言码的字符串。
- 未匹配则取区域支持列表首项；不可用时返回 en。

因此，明确调用 `region=HK, initLocale=zh` 且列表 `[zh-HK,en]` 时会得到 zh-HK。
但目前静态调用端是 `MLocale.INIT_locale`，它传入的是系统 countryCode，
不是 selected Compass region。`MLocale.setup` 优先用 UserDefaults 保存的 locale；
`setupI18nBaseInfo:compassUpdateScene:` 不直接更新 MLocale。
Mach/MSI 均存在显式 updateLocaleIdentifier 桥接入口，但选区页面的调用参数和优先级
本轮未还原。因此本页不将上述默认算法当成选区后的完整自动转换规则。

后续如需完整恢复该分支，可从抓包 193 的 checkUpdate 映射继续：
`mach_pro_sailor_choose_location_page` 版本 0.0.50 对应下载条目 293，包体已在抓包中；
本轮没有为此继续展开页面包逆向。

## 紧凑证据索引

全部静态行号对应 `dump/Keeta.dec.asm`：

| 行号 | 证据 |
|---:|---|
| 13661082 | setupAccount 设置固定 joinkey |
| 13661169、13664273 | 设置 getI18nConfig block → bizCoreParams |
| 17167350、17167387 | lang 取 MLocale，joinkey 取 SOAAccountConfig |
| 17173284、17173321、17173367 | Passport 坐标 getter 与 lastLocation/marsLocation 来源 |
| 18054574、18054636、18054984 | MLocale 当前值、更新与 setup 持久化优先级 |
| 18055033、18055106 | INIT_locale 的系统输入与默认语言匹配调用 |
| 18067475、18067516 | getRegionConfigs callback 消费 data |
| 18077970、18078689 | 语言配置读取回退与更新持久化 |
| 18078753、18079254、18079592 | 区域支持列表、默认语言匹配、mapping 组匹配 |
| 18203767、18203876 | currentLocalInfo 状态应用与 bizCoreParams 消费 |

本页只记录公共配置、字段名和证据位置；不复制当前身份、签名、token、邮箱或密文材料。
