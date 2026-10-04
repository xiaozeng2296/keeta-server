# 注册链路当前实现

> 历史研究资料，来源 `codex/keeta-project@6197c528`；保留当时的观测与未完成项，不代表新项目当前状态。当前规则见 [字段状态](../MTGSIG_FIELDS_STATUS.md)，复跑入口及已修正结论见 [离线研究指南](../research/OFFLINE_RESEARCH.md)。文中的旧 `dump/`、抓包及设备路径仅作证据索引，原材料未随仓库发布。

`keeta_offline_flow.py` 默认按 Charles 抓包的实际顺序执行。当前识别 13 类核心接口；新机抓包包含
20 条请求，两条 OneID、两条 scfg 和重复区域请求均保留；旧抓包有 21 条（其中三条 scfg），
但没有拍到 OneID 和 Compass 阶段。
这不是全部后台流量的重放器，也还不是已验证成功的邮箱注册器。

当前状态转换：

1. `/uuid/oversea/ios/register`，`requiredId=4` 返回的 `data.unionId` 更新 csecuuid/uuid。
2. 同一路径 `requiredId=1` 返回的 `data.unionId` 更新 pragma-unionid。
3. `/sdkapi/newreg` 使用恢复的独立 SHA1 签名；上述三个请求不附加 mtgsig。
4. 后续签名从本地 a7/a8 开始；info/report 成功后更新 a7，v5/sign 成功后更新 a8。
5. 每一步先构造本次请求体，再签名、发送、校验响应，然后构造下一步。
6. Compass 的真实响应提供明确区域路由；服务区域列表的真实响应提供候选城市/坐标；
   currentLocalInfo 确认所选区域/城市后才提交区域状态，更新后续对应 host、header 和已有 query 字段。

info/report 和 v5/sign 的先后顺序依实际抓包；重复的 bio/device-info/confirm 请求不去重。
confirmProtocol 启动阶段为 JSON，登录前为表单，各自按抓包编码构造。

## 签名配置与计数生命周期

FullSigner 已按抓包恢复的字段生命周期更新：

- a10 使用会话内保持的 signature_counter，不随每次请求递增。
- a5 明文 b2 使用逐请求递增的 sign_sequence。
- b3、b7、b8、b9 保留采集状态；b8/b9 是缓存采集时间，新机包 73 条中完全固定，不能逐签刷新。

不能把所有看起来像计数或时间的字段统一改成请求序号/当前时间。身份档持久化与服务端
响应回填必须沿用同一会话状态，重签后再提交最终 URL/body。

a5 的 signing_profile 与缓存 a9 的 a9_profile 分别识别和保存。a9 可能来自另一配置的
缓存，不能用它决定本次 a5 的 provider。RPC `/decrypt` 已对 a5 独立识别已支持的配置；
显式指定 signing_profile 时按指定配置验证，不能静默用其他配置掩盖不匹配。

当前新机包 73/73 组签名已完成 a5 解码与完整 a2 对拍；旧包完整 a2 为 64/65，一组较大
body 仍待排查。该边界限制旧抓包的全部覆盖结论，也不代表服务端已接受新注册请求。

## 提供设备内容

`mtgsig.bootstrap_identity.bootstrap_identity(uuid, timestamp_ms, base=...)` 生成首阶段本地
a7/a8，并保留已有服务端身份。它不会伪造完整设备画像；a1、a5 的 base_collect、a9 的
SIUA 等由明确的设备/SDK资料提供。使用同一画像贯穿全部字段，不从 dfp 推导硬件内容。

profile 的 B 指纹输入可以是 `fingerprint_obj` 或 `fingerprint_plain_json`。每一步重新编码：

- I20 读取 idfv；I40 读取 csecuuid；I18 读取 passport 的 device_id（与 idfv 分开）。
- I39 更新毫秒时间；`fingerprint_dynamic_fields.I39` 可保留明确的浮点毫秒文本。
- I41/I44 只有显式提供新测值才替换，不把时间变化伪装成设备采集。

也可明确提供已编码 `fingerprint`，但不能同时提供明文源，否则拒绝歧义。

## A envelope 明文配置

profile 中 `envelope_payloads` 以步骤名为键：`fingerprint_info`、`v5_sign`、
`device_info`、`bio_report`。各接口的内容独立，不能把一个密文套给所有接口。

下面只演示构造接口，不是完整注册画像：

```json
{
  "envelope_profile": "default",
  "envelope_mode": "twofish-mod",
  "envelope_payloads": {
    "v5_sign": {
      "plaintext": {"m3": "Keeta", "m153": "待本次OneID返回"},
      "bindings": {"m153": "csecuuid"},
      "transform": "m-series"
    }
  }
}
```

`bindings` 只替换明确指定的顶层字段，然后进行字段变换与压缩加密。
`transform="m-series"` 使用 `corpse_codec` 的固定表；特殊字段可明确指定
`passthrough`，没有自动豁免。包括 `m137` 在内的字段变换已通过原生整对象调用对拍；
正确边界为字节 32..125，`~` 原样保留。是否需要变换仍取决于采集路径的 mode：当前
sign/info 的 mode=0 返回缓存原值，不能再按 mode=1 解码或无条件加一次变换。
输入配置需与明确的采集阶段匹配，见 `CORPSE_CODEC.md`。
不想重新序列化已有 pre-deflate 数据时，使用 `{"raw_plaintext":"完整原始JSON文本"}`；
该方式不能混用 bindings 或 transform。缺绑定源或压缩产生原生短输入问题时停止，不回退旧密文。

执行器在一个会话生成一次 16B envelope key，各步骤共用。可通过
`envelope_session_key_hex` 显式提供并保留会话 key；该值不应写入公开日志。
SDK 加解密与任意公开信封不能反 RSA 的边界见 `ENVELOPE_SDK.md`。

外层字段可通过 `request_body_fields[完整接口路径]` 明确提供当前值，例如 v5 的 time、
bio 的 index/regionPath。v5 的 time 是 `YYYY-MM-DD HH:MM:SS` 字符串，现有证据不足以
确定设备时区，程序不擅自用服务器时区改写。bio index 是字符串计数，regionPath 是 JSON
数组字符串；它们与 envelope 内字段是两个层次。加密字段必须走对应 payload 配置。

库调用还可传 `execute_offline_flow(..., payload_builder=callback)`，callback 每步在
签名前接收当前 profile 和毫秒时间，返回明确更新过的 profile。

## 运行与验证边界

```sh
python3 keeta_offline_flow.py --capture 新机之后尝试登录.chlsj \
  --profile current_profile.json --identity current_identity.json
```

默认只构造并打印步骤状态，不消费抓包响应，也不把旧响应当成本次下发。
添加 `--send` 才发送，并按实际成功响应推进；`--identity` 保存计数器和收到的身份字段。
后续构造缺资料、签名无效或响应失败时停止。

已验证：原生/历史密码对拍、OneID 的两种下发语义、独立本地身份生成、真实 FullSigner
与注入响应的整段构造测试、RPC HTTP 编解码。现有两份抓包的登录 confirm 返回 403、
userriskcheck 返回 user_risk_deny；没有成功 apply/发码响应，所以不能声称全链路已放行。
复现入口见 `tests/test_registration_payloads.py`、`tests/test_registration_execution.py`
与 `OFFLINE_CHAIN_AUDIT.md`。

## 邮箱协议衔接

`mtgsig/login_protocol.py` 已静态恢复 risk、signup/login apply 与验证码提交的请求字段。
请求为 form snake_case，响应从 `data.userTicket`、`data.isSignup`、`data.email`、
`data.serialNumber` 精确读取。`isNormal` 不作为有效票据的额外阻断条件；公共 device_id
来自 IDFA，不是 IDFV。注册 password 使用独立登录公钥进行 RSA PKCS#1 v1.5 加密。

主 flow 的 risk body 使用同一构造器，执行时没有有效 userTicket 就停止。
`keeta_login.plan_signup_flow()` 可从 risk 区域上下文构造未捕获的 apply/submit 路径；
旧 camelCase overrides 仅在 Python 调用边界兼容，最终 wire 始终 snake_case。
缺本次 ticket、serial 或验证码时返回错误，不复用历史模板状态。
`run_one()` 以当前 risk 分支推进，错误响应不会继续收码；最终账号 token 路径仍需
显式、已验证的 token_path。上述本地恢复和注入响应测试不代表实际发码或注册已成功。
具体调用和 RVA 证据见 `LOGIN_PROTOCOL_STATIC.md`。

## scfg 已接入主执行器

主 flow 按抓包顺序保留每次 `/v1/scfg`。调用者提供 `scfg_inputs`：

```json
{
  "scfg_inputs": {
    "raw_fields": {"m154":"com.example.sandbox", "m144":"3.12.401", "m136":""},
    "os_version":"16.2", "sdk_version":"5.21.10", "city":"", "user_id":null
  }
}
```

`city` 是 SDK 环境中的城市名称，不能拿区域接口的 cityId 替代；当前历史请求值为空字符串。
构造时内层 uuid 使用本次 profile.csecuuid，dfpid 使用当前签名器 a8（v5/sign 成功后为
服务端 DFP），timestamp 使用当前毫秒。缺失明确输入就停止，不发送抓包里的旧 data。
每次响应必须成功解密 `data.resStr` 后才继续；配置、applist 标志和累积 private fields
更新主 flow 状态与身份档，供后续步骤和接续使用。未验证字段没有附加作用。
`tests/test_registration_execution.py` 验证真实签名器下的 sign→scfg→scfg 状态流；
该禁网验证不等于服务端验收。

## 区域三接口的 profile 与状态

主执行器已接入 `compass → service_regions → current_local_info`，仍按抓包实际顺序保留
重复调用。区域请求使用专用构造器，`device_id`、邮箱或 B 指纹不会进入区域表单。
调用者提供本会话的应用/系统输入，不使用历史响应填补缺失状态：

```json
{
  "region_inputs": {
    "app_id": "517",
    "app_version": "3.12.401",
    "initial_region": "GG",
    "initial_city_id": "1234567890",
    "selected_region": "HK",
    "service_route_region": "HK",
    "app_session": "本次统计会话的 appSession",
    "service_request": {
      "userType": 1,
      "bundleName": "mach_pro_sailor_choose_location_page",
      "bundleVersion": "0.0.50"
    },
    "local_info": {
      "actualLatitude": "",
      "actualLongitude": "",
      "clientType": "c_ios",
      "systemLocale": "zh",
      "systemRegion": "",
      "systemTimeZone": "GMT+08:00"
    }
  }
}
```

上述内容展示已观测流程的输入形状，`app_session` 必须替换为同一会话的真实生成值。
也可由 `header_overrides.appSession` 提供它；不会沿用模板旧值。
`selected_region` 是调用者的目标选择；`initial_region/initial_city_id` 是尚未完成选择时
明确的启动配置，不能把目标选择直接当作服务端已确认状态。

`service_route_region` 是显式入口选择：示例 HK 只让服务区域列表请求取已接受 Compass
中 HK 的 `Keeta.C.ProductUrl`，请求 header 仍保留当前 GG 状态，复现已验证成功的
region_08。省略时使用当前状态的区域；失败不会触发自动换 host 或重复发送。
currentLocalInfo 初次沿自己的抓包路由，选区成功之后才使用对应的已确认路由。

服务区域列表只在成功收到本次 Compass 后构造；currentLocalInfo 只在本次候选包含
`selected_region` 时构造，其 `latitude/longitude` 取候选的城市坐标。
`local_info` 不接受自行覆盖这些选区坐标；真实定位值与系统值由其余六个字段明确输入。
不能再通过 `request_body_fields` 绕过区域专用构造器。

执行器按有效响应保存：

| 字段 | 来源及用途 |
|---|---|
| `region_compass_response` | `{ "http_status": 200, "response": 完整本次Compass业务JSON }`；重新验证唯一地区快照 |
| `service_region_candidates` | 本次服务区域列表，按 region 保存 city_id/latitude/longitude |
| `region_state` | currentLocalInfo 返回的 region/city_id 与原始 locale/lang/time_zone/currency |
| `compass_snapshot` | 与已确认地区匹配的四项核心路由快照；不推定 private/active/recovery 优先级 |

这些状态会写入签名器身份档并传给下一请求。续接可以从同一会话的身份档恢复，也可显式
提供前次已接受的上述状态。单独的旧 `compass_snapshot` 不足以恢复当前执行器所需完整
Compass 响应。旧抓包没有 Compass 请求，必须由调用者提供已接受的配置续接；否则显式失败。
库函数 `build_offline_plan` 不消费模板中的 response，故未提供续接状态时会把依赖后续响应的
请求报告为缺状态，而不会伪造完整成功计划。

currentLocalInfo 必须同时匹配所选 region 和本次候选 city_id，之后才更新有效状态与
region/city header。后续匹配到已知产品、Passport、pikachu、push、i18n host 家族的请求
按已确认配置选 host，并同步显式 Host header；已有 `ci/cityId/region` query 值也相应更新。
无关联的 host 不变。原始 locale/lang 只保存在状态中，不推导 `zh-HK` 或修改 language query。

有 `identity.base_collect.b7` 时，执行器同时记录区域事件。`b7` 是已恢复的 SDK 启动秒数；
若传 `sdk_launch_seconds`，它必须与 b7 一致。事件累计值严格按原生计算顺序：

```python
elapsed_ms = math.trunc((event_seconds - sdk_launch_seconds) * 1000.0)
```

不能先将 epoch 秒转换成整数毫秒再相减，浮点边界会相差 1ms。接收并验证
currentLocalInfo 后，`clock()` 一次取当前秒数，保存 `region_response_applied_at_seconds`
及对应毫秒；地区发生变化时追加 `region_events`，保存 `region_event_at_seconds`/
`region_event_at_ms`，同步 `base_collect.b22` 和已配置的 `reporting_inputs.bio_report.region_events`。
它表示从固定启动点到事件的累计毫秒，不是上一个地区的停留时间。

已观测 b22 中的初始事件保留，不补造其历史 wall clock。没有既有事件时才把本次应用初始
状态的当前时刻记录为新事件；缺 b7/明确启动基线时只保存真实响应消费时刻，不伪造累计值。
回归入口为 `tests/test_registration_region_flow.py`，包括响应依赖、失败停止、显式 HK 入口、
真实坐标传递、持久化接续与原生浮点边界。
