# 完整新设备抓包：邮箱注册登录链路

> 历史研究资料，来源 `codex/keeta-project@6197c528`；保留当时的观测与未完成项，不代表新项目当前状态。当前规则见 [字段状态](../MTGSIG_FIELDS_STATUS.md)，复跑入口及已修正结论见 [离线研究指南](../research/OFFLINE_RESEARCH.md)。文中的旧 `dump/`、抓包及设备路径仅作证据索引，原材料未随仓库发布。

来源：`完整版新设备注册登录.chlsj`，778 条记录，83,181,326 字节。
SHA-256：`5f218afcfe01a3a1acedee5938753ccf2528e4d2d8603c26553c03d39153013a`。
全部索引为零基数组索引。审计仅解析本地原包，没有发请求、接收邮件或操作手机。
本报告不记录邮箱、验证码、票据、设备标识或账户 token 原文。

## 成功链路已完整出现

| 索引 | 路径/阶段 | HTTP | 响应及意义 |
| --- | --- | --- | --- |
| 50 | `confirmProtocol` / `install_splash` | 200 | `code=0` |
| 112 | `confirmProtocol` / `region_switch` | 200 | `code=0` |
| 584 | `confirmProtocol` / `login_register` | 200 | `code=0`，携带当前完整邮箱 |
| 585 | `/api/emaillogin/v1/userriskcheck` | 200 | `data.userTicket`；`isSignup=true,isNormal=true,hasEmail=true,hasMobile=false,hasPassword=false` |
| 589 | `/api/emaillogin/v1/emailsignupapply` | 200 | `data.serialNumber`、`data.email` |
| 601 | `/api/emaillogin/v1/emailsignup` | 200 | 顶层 `user.token/id/idStr/email/registerRegion/tkContext` |
| 604 | `confirmProtocol` / `login_register` | 200 | `code=0`，携带登录后的用户 ID 与 token |
| 605 | `/api/v1/userinfo/userRedDot` | 200 | `code=0`，使用索引 601 的账户 token |
| 606 | `/api/compcenter/v1/account/getAccountDeregistrationStatus` | 200 | `code=0`，使用同一账户 token |

本次抓包补齐前一份成功片段缺失的有效 risk 票据来源，确实观察到
`risk → signupapply → signup → 已登录接口成功` 全链路。
它证明捕获的 App 会话成功；不等于现有协议程序的新身份已经通过 live risk。

## 时间、地区和真实业务主机

登录三步的查询上下文均为 `region=BR`、`cityId=102302389`、`locale=en`。
索引 585、589、601 的抓包 `host` 字段都是 `fooddelivery-eu.mykeeta.com`，
但各自 HTTP/2 `:authority` 都是 **`passport-eu.mykeeta.com`**。
`:path` 与表格里的三条 Passport 路径一致。
因此构造重放 URL 时不能单独使用 Charles flow 的 `host`，应优先使用原请求业务 authority。
`M-SHARK-TRACEID` 存在，但这里已有明确 `:authority`，无需从 trace ID 猜测路由主机。

相对时间（以索引 584 requestBegin 为起点）：

| 事件 | 时间 |
| --- | --- |
| 登录同意开始 | +0 ms |
| risk 开始 | +58 ms |
| 登录同意响应 | +309 ms |
| risk 响应结束 | +426 ms |
| apply 开始 | +1,190 ms |
| apply 响应结束 | +1,990 ms |
| submit 开始 | +17,134 ms |
| submit 响应结束 | +17,555 ms |

risk 在 confirm 响应到达前已经发送，说明该同意上报不是 risk 的已完成响应前置条件。
本条三步表单没有 `request_code/response_code` 字段，没有观察到这条登录分支需要挑战结果。

## 票据、发码序号和账户状态关联

以下关系均在原始值上比较，仅记录布尔结论：

| 关系 | 结果 |
| --- | --- |
| `#585.response.data.userTicket == #589.request.user_ticket` | true |
| `#585.response.data.userTicket == #601.request.user_ticket` | true |
| `#589.response.data.serialNumber == #601.request.serial_number` | true |
| `#584.request.email == #585.request.email` | true |
| `#589.response.data.email == #601.response.user.email` | true |
| risk `token_id` 与当前 App 配置常量一致 | true |
| 三步 `device_id` 相同 | true |
| 三步 `tk_context_plain` 相同 | true |
| 三步 fingerprint 密文字节相同 | false |
| apply/submit 的 `username/password` 都为显式空串 | true |
| submit 验证码长度 | 4 |
| `#601.response.user.id` 与 `idStr` 一致 | true |

索引 604、605、606 的 `header.token` 均等于索引 601 返回的 `user.token`，
其 `header.userid`、`header.csecuserid`、`query.userid` 均与同一个返回用户 ID 一致。
后续共有 17 个请求 header 精确使用该 token；其中多个业务接口 `code=0`，
因此成功判断有账户接口实际消费证据，不只是 HTTP 200。

## 必须处理的邮箱脱敏

risk 请求使用完整邮箱；apply 和 submit 响应均返回**显示用脱敏邮箱**：

```text
完整地址的 local-part 前 3 个字符 + "***" + "@" + 完整原域名
```

本包 local-part 从 16 个字符变为 6 个字符：前 3 字符保留，后面固定连续 3 个星号，
没有保留 local 后缀。显示前缀与原邮箱匹配，完整域名也匹配。
固定 3 个星号不代表被隐藏字符的实际数量。

这产生了真实实现差异：

- `#589.data.email` 和 `#601.user.email` 不等于 risk 的原邮箱，即使 strip/casefold 也不等。
- 审计起始版本的 apply 状态转换要求完整邮箱相等，因此错误地拒绝成功发码响应。
- 审计起始版本 `parse_submit_response(expected_email=原邮箱)` 同样拒绝真实成功响应；
  不传 expected_email，或把 apply 的显示邮箱作为 expected_email，则返回账户状态。
- 不能把脱敏字符串写回作为接码邮箱；收件人必须保留本次 risk 输入的完整原邮箱。
- 受限显示模式只能证明与当前地址的可见部分兼容，不能唯一识别邮箱。
  关联证据仍是同一次 risk 的 userTicket、apply 的 serialNumber 和本次验证码提交。

复查 `发送验证码并成功登录.chlsj` 也得到同样模式：
索引 19 confirm 含完整邮箱，索引 14 apply 和索引 30 submit 返回前 3 字符加固定星号的显示邮箱。
此前用 apply 响应邮箱作为 submit parser 的 expected_email 做对拍，只验证了两次响应的一致性，
没有验证它与原始收件地址的兼容关系。此报告补正该证据范围。

## 离线参数对拍

现有 `login_protocol` 参数构建器用各条原始字段在内存重建，不发送请求：

| 索引 | 构建函数 | 原表单逐字节一致 |
| --- | --- | --- |
| 585 | `build_risk_body()` | true |
| 589 | `build_apply_body(signup=True)` | true |
| 601 | `build_submit_body(signup=True)` | true |

`parse_risk_response()` 接受有效票据及 signup 分支；`parse_apply_response()` 能解析邮箱和序号。
需要修正的是 response 显示邮箱的绑定处理以及 HTTP/2 authority 优先级，
并非重写整套登录表单算法。

## 本轮修复验证

`parse_apply_response()` 新增 `expected_email`；与 `parse_submit_response()` 共用受限显示模式校验。
提供原完整收件地址时，结果 `email` 保留该原地址，显示模式另记
`display_email` 和 `email_match="masked"`。只匹配上述固定三字符前缀格式，
拒绝任意星号通配、错误前缀/域名、已脱敏的 expected_email。
token 和用户 ID 的严格判据保持不变。

`keeta_login` 模板装载使用请求 authority，去除捕获认证头；
执行器在 apply/submit 校验中绑定原始邮箱，邮箱快照和接码仍使用完整原地址。
`tests/test_login_protocol.py` 的 17 项测试和 `tests/test_login_execution.py` 的 13 项测试通过，
均使用合成测试资料并禁止网络调用。

两份真实成功包修复后再次离线验证：apply 与 submit 都能解析，
都保留原完整收件地址并标记 masked，业务主机均为 `passport-eu.mykeeta.com`，
装载模板没有继承捕获账户认证头。没有重放历史票据、验证码或账户 token。
