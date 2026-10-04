# 注册流程未接入配置接口的数据依赖审计

> 历史研究资料，来源 `codex/keeta-project@6197c528`；保留当时的观测与未完成项，不代表新项目当前状态。当前规则见 [字段状态](../MTGSIG_FIELDS_STATUS.md)，复跑入口及已修正结论见 [离线研究指南](../research/OFFLINE_RESEARCH.md)。文中的旧 `dump/`、抓包及设备路径仅作证据索引，原材料未随仓库发布。

本轮只读 `新机之后尝试登录.chlsj` 和项目反汇编/实现，没有网络、手机、邮箱操作，
也未修改主 flow。目标是找响应向后续请求传递的状态，而不是按接口名称排列必经步骤。

最重要的缺口是**区域选择结果与区域路由配置的一致回填**。目前证据不支持将 bind 或
scfg 当作首次 v5/sign 的必经前置；scfg 现已恢复独立 AES codec，主 flow 接入且真实 HTTP200/code0。详见 [SCFG_SOURCE](SCFG_SOURCE.md) 和 `dump/registration_session/reporting_live_01/`。此页以下原始匹配审计范围不包含后来恢复的内层。

## 证据范围与时间顺序

- Charles 条目共 726，以下索引均从 0 开始。
- SHA-256：`eb97148df243d6a16855914d959f707eaa9086256ca903bcc44bd17411dcc1d0`。
- 匹配范围：请求 URL/host、query、headers、JSON/form body、成功解码的全部 73 条 a5，
  以及请求中 15 个 B fingerprint 对象。A envelope、scfg 内层数据仍为不透明内容。
- 工具：`tools/audit_registration_config_capture.py`。结果为
  `dump/registration_config_dependencies/audit.json`，只保存索引、字段路径与公开配置值，
  不保存 token、设备标识、client IP 或密文配置值。
- `later_matches` 要求请求 `requestBegin >= 来源响应 end`；抓包索引不是响应完成顺序。
  相等只是数据流候选，需结合字段语义、时间与实际代码。例：metaConfig.version 恰好等于
  某次 a5.b2，不是版本号进入签名计数的证据。

| 事件 | 本地抓包时刻 |
|---|---|
| 16 v5/sign 请求开始 / 响应完成 | 01:07:28.154 / 01:07:28.217 |
| 4 getRegionConfigs 响应完成 | 01:07:28.720 |
| 21 newreg 请求开始 / 响应完成 | 01:07:28.579 / 01:07:28.736 |
| 65 fingerprint info 响应完成 | 01:07:29.747 |
| 97 getCompassConfigs 响应完成 | 01:07:32.118 |
| 205 currentLocalInfo 响应完成 | 01:07:41.673 |
| 244 首次 scfg 请求开始 / 响应完成 | 01:07:42.419 / 01:07:42.465 |

因此，本次首个 sign 已先于这些实时配置响应完成。它使用的默认/已有配置不能由这次后到
响应解释；但这也不证明所有设备和版本都能完全没有配置。使用明确的配置快照与“每次先请求
这些端点”是两个不同实现选择，不能从同一批流量混为一谈。

## 按首次出现排序的最小缺失依赖表

“缺失”包含未接入端点，以及已调用端点却未消费的响应状态。下表不是新必经接口清单。

| 首次索引 | 来源与状态 | 后续证据 | 当前可作出的结论 |
|---:|---|---|---|
| 4 | getRegionConfigs：`data.supportRegions.HK.supportLocales[0]`、`data.cityList[3].cityId` | 支持语言为 zh-HK；城市为 810001。后续 627/628 的 lang/locale、cityId 与这些公开配置一致 | 区域/语言候选字典有后续使用；同值也出现在其他配置来源，不能单靠相等把 4 定为唯一来源。首个 sign 未等它返回 |
| 21 | newreg：`pushtoken` | 与 102、220 的 `headers.PushToken` 逐字相等；两次均在 newreg 完成后 | 这是已证实但尚未回填的 push 支线状态。未观察到它直接进入核心请求、a5 或 B；不是首个 sign 的前置 |
| 25 → 82 | metaConfig：`data.resourceUrl` → 下载 i18nconfig_prod.json | 25 返回 URL 与 82 的完整请求 URL 相等。资源里的 `i18n.capitalCityIdByRegionMap.HK=810001` 与后续城市一致 | 资源获取链确实发生；可作为明确配置快照来源。`data.version` 目前没有可证实的核心状态传递 |
| 97 | getCompassConfigs：`data.configs[*].bizConfig.platformHosts` | HK 的 `Passport.url` 对应 628 host，`Keeta.C.ProductUrl` 对应 627；MSP/Push 地址与后续接口相符 | 区域路由数据的明确来源。SDK 静态代码确实读取 Passport.url；初始 MSP/Push 地址在 97 返回前已使用，说明本次网络获取不是这些首请求的前置 |
| 102（重复 220） | sdkapi/bind：响应只有 `errormsg` | 两次都是成功文本，无新增 token/dfp/xid/uuid；下游明文未命中该文本 | bind 消费 push token 与客户端 thirdtoken，不提供已观察到的登录状态。不能凭路径把它当设备身份下发 |
| 161（重复 257） | getOpenServiceRegion：`data.regionList`、`data.structRegionList` | 返回 7 个可选区域，structRegionList 为 HK；之后 205 明确下发 HK 城市信息 | 区域选择候选/界面数据，未证明它单独决定后续状态；不是账号票据 |
| 205 | currentLocalInfo：`data.region`、`data.cityId`，另有 locale/lang/timeZone/currency | 返回 HK/810001 后，217 DNS 参数、220 push country/header、244/248 SDK query/header、627/628 登录 query 相继使用；此前请求中无相同 HK/810001 状态 | **最清晰的缺失状态转换。** 需保存选择结果，再据区域路由配置构造后续请求；不能只保留首次 GG 模板 |
| 244（重复 464） | scfg：`data.serverTimestamp`、`clientIp`、`interval`、`resStr` | 可见值未直接复用到后续明文、a5、B；两次 resStr 相同、interval=0，timestamp 相差 6668ms | 已恢复 data.resStr 解密及 applistOpen/privateCollectArr 消费，已接入主 flow 并真实成功；不能据此认定其它响应字段用途 |
| 476 | getUserProtocol：`data[]` 的 type/protocol/version/title | 627 confirm body 无这些响应值或版本字段；其 placementId 也已在 476 请求中提供 | 已观察到条款展示数据，没有观察到响应字段回填进 confirm/risk；不能凭条款 UI 端点推断新签名材料 |

## 区域与路由：应如何解释现有证据

205 的响应为区域 HK、城市 810001；请求进入该端点时仍是 GG 上下文。
同一响应的 locale/lang 是 `zh`，后续不少请求转成 `zh-HK`，627/628 也是 zh-HK。
4 已提供 HK 支持语言 zh-HK；这说明还存在区域语言适配过程，不能把响应 locale 原样写入所有后续请求。
本轮尚未还原这一适配的完整算法。timeZone 为 GMT+08:00，但相同值在 205 以前就出现，
因此不能认定本次响应是它的首次来源；currency 没有直接 request 命中。

97 的 platformHosts 使用**带点的字面 key**，不是递归对象路径，例如
`data.configs[1].bizConfig.platformHosts["Passport.url"]`。

| 配置区域 | Passport.url | msp.url.pikachu | Keeta.C.ProductUrl |
|---|---|---|---|
| GG | passport-hk.mykeeta.com | pikachu.mykeeta.com | https://fooddelivery-eu.mykeeta.com |
| HK | passport-hk.mykeeta.com | pikachu.mykeeta.com | https://fooddelivery.mykeeta.com |
| BR | passport-eu.mykeeta.com | pikachu-eu.mykeeta.com | https://fooddelivery-eu.mykeeta.com |

该表只记当前捕获配置，不建立全球永久映射。本包实际切换到 HK，不能把 GG/BR/HK 的
host、region、city 与语言混用。原先把这个新机包称为“巴西登录流程”会掩盖这次实际选区。

配置还有 commonConfig、privateConfig、activeStrategy 和 recoveryConfig 等层。
本轮仅核对最终请求与 configs 中的具体值，没有完整恢复这些层的优先级与回退机制。
不能把匹配到一个 host 就声称整个 Compass SDK 已复现。

项目反汇编提供了独立消费证据：

- `dump/Keeta.dec.asm:17198931`：passportHostUrl 读取 `Passport.url`；完整路径证据见
  [LOGIN_PROTOCOL_STATIC](LOGIN_PROTOCOL_STATIC.md) 的 RVA `0x2b5bc50`。
- `dump/Keeta.dec.asm:18204193`：SLCAppI18nInterfaceService 发 currentLocalInfo；
  回调 `sub_102DF4A58` 在行 18204340 取 data，行 18204356 调
  `setupI18nBaseInfo:compassUpdateScene:`，随后更新公共参数。
- `dump/Keeta.dec.asm:18222800`：SLCoreParamsService 同样发 currentLocalInfo；
  回调 `sub_102E01790` 在行 18223378 取 data，行 18223529/18223531 保存 i18nBaseInfo，
  并在行 18223650 更新公共参数。另有本地 fallback，不能声称网络是唯一来源。
- `dump/Keeta.dec.asm:18339131` 与回调 `sub_102E4EA1C`：区域选择管理器的同名接口，
  data 进入 response，再交给 regionSelectionRequest:finished:。

这些静态分支证明响应被用于区域状态；不能仅凭这份流量判断当次走了三个入口中的哪一个。

## Push 与 scfg 的界限

newreg 的 token 匹配结果仅保留来源和两个消费位置，没有输出 token。
bind 请求自身只有 country、thirdtoken、thirdtype，鉴别 push 会话的值放在 PushToken header。
thirdtoken 不等于 newreg token；本轮未凭命名把它直接认定为某个设备密钥，也未恢复其生成过程。
两次 bind 的响应只有成功文本。若要复现 push 支线，需要单独保留该状态；现有证据不足以将
bind 成功列为下游 userriskcheck 接受条件。

scfg 的 body 是 `os`、`mtg_version` 和长度 408 的 data 字符串；返回内部 resStr 长度 108。
它不是现有“两段 RSA + CBC”信封格式已验证适用的证明，不能把已恢复 A codec 直接套上去。
两个响应的 clientIp/resStr/interval 相同，只有 serverTimestamp 改变；请求相隔约 6.66 秒。
interval=0 不足以证明它是轮询周期或禁用开关，字段语义待恢复。

此次没有看到 clientIp、serverTimestamp、resStr 被直接写回已可见后续请求；它们仍可能经
派生或藏在未解的 A payload 中使用。`audit.json` 的零命中只限定本轮可见域。
尤其不能根据这点删除 scfg、伪造其响应或把它当缺少某把固定 key 的证据。

## 可据此推进的最小实现边界

对于父级正在做的首次 sign 验证：保留匹配 SDK 的配置快照、正确区域上下文和当前设备画像，
现有流量证据没有要求先加 bind/scfg 请求。首个 sign 的输入画像是否正确仍须独立验证。

若继续推进区域切换后的注册与邮箱请求，下一个明确可实现的状态对象是：

1. 当前 region/city 与区域语言结果；不能把城市或 locale 候选列表直接当已选择状态。
2. 匹配区域的 Passport/业务/MSP/Push 路由快照，并保留配置版本/来源。
3. 仅在需要 push 支线时消费 newreg.pushtoken，再由 bind 使用；与 a7/a8/OneID 状态分开。
4. scfg 为已恢复的独立配置协议，必须用本次 OneID/DFP/时间构造，并消费本次响应中的 data.resStr；不代表整条发码链已完成。

现有两包仍没有成功发码；这些依赖证据解释客户端状态，不证明服务端风控会因此放行。

```sh
python3 tools/audit_registration_config_capture.py
```

工具针对本抓包的固定索引，并先校验关键端点位置；输出不含 token、设备标识或客户端 IP。
它是只读证据生成器，不是新增的网络注册执行器。


## 独立状态适配器

`mtgsig/region_state.py` 已实现以下纯解析入口，尚未接入主 flow：

```python
parse_current_local_info_response(response, *, http_status)
parse_compass_response(response, *, region, http_status)
```

两者要求 HTTP 为整数 2xx、顶层 code 为整数 0、data 为对象且没有明确 error/success 失败。
无效响应返回空字典，验证完成前不产生部分 patch，也不修改原响应。

currentLocalInfo 输出 region、city_id；存在时再原样保留 locale、lang、time_zone、currency。
region/city_id 只读 data.region/data.cityId，leafCityInfo.cityId 不是同一城市层级，不作回退。
模块不执行 zh→zh-HK 转换，调用方不能把原始语言值直接当全部后续请求的最终 locale。

Compass 必须显式指定 region，只接受 data.configs 中唯一匹配的条目。输出
compass_version、compass_region、compass_source=`data.configs`、platform_hosts；
后者仅含 Passport.url、msp.url.pikachu、Push.medusaUrl、Keeta.C.ProductUrl 四个字面 key。
缺失/歧义/格式错误整体拒绝，不通过其他配置层猜补。

这个输出特意命名为配置来源快照，没有覆盖当前 region，也没有执行 commonConfig、
privateConfig、activeStrategy、recoveryConfig 的未恢复优先级，因此不是 Compass 最终
有效路由算法的完整复现。`tests/test_region_state.py` 的 7 项测试包括真实 97/205 响应，
核对 HK 路由与后续 627/628，测试禁止 socket。
