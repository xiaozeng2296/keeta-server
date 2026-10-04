# Keeta 邮箱协议链

> 历史研究资料，来源 `codex/keeta-project@6197c528`；当前规则见 [字段状态](../../MTGSIG_FIELDS_STATUS.md)，复跑入口及已修正结论见 [离线研究指南](../../research/OFFLINE_RESEARCH.md)。旧抓包、身份与运行路径仅作证据索引，原材料未随仓库发布。

当前已从 iOS 二进制恢复 risk、apply 和验证码提交的请求字段，及 userTicket、serialNumber
响应路径。实现与证据见 `mtgsig/login_protocol.py` 和 [LOGIN_PROTOCOL_STATIC](../LOGIN_PROTOCOL_STATIC.md)。
`完整版新设备注册登录.chlsj` 已证明 BR 区域完整的 risk→发码→4 位验证码注册→账户接口成功；
#585 的 userTicket 与 #589/#601 两步请求精确关联。账号响应为顶层 `user`。
实际业务 authority 为 passport-eu，而不是 Charles 外层记录的连接主机 fooddelivery-eu。
当前协议 HK 身份仍停在 risk 拒绝，不能把原生抓包成功当成协议实测成功。
脱敏总报告见 [FULL_REGISTRATION_LOGIN_CAPTURE](../FULL_REGISTRATION_LOGIN_CAPTURE.md)，之前片段见 `docs/SUCCESSFUL_LOGIN_CAPTURE.md`。

## 请求顺序与字段

所有路径前缀为 `/api/emaillogin/v1/`，POST form，UTF-8。

| 阶段 | 接口 | model 请求字段 | 继续条件 |
|---|---|---|---|
| 风控 | userriskcheck | email、request_code、response_code、token_id | data.userTicket 为有效字符串 |
| 注册发码 | emailsignupapply | user_ticket、username、password | data.email 和 data.serialNumber |
| 登录发码 | emailloginapply | user_ticket | data.email 和 data.serialNumber |
| 注册提交 | emailsignup | user_ticket、username、password、email_code、serial_number | 顶层 user.token、有效且一致的 id/idStr、当前邮箱 |
| 登录提交 | emaillogin | user_ticket、email_code、serial_number、request_code、response_code | 共用严格 user 解析；旧账户分支尚无成功抓包 |

request_code/response_code 缺失时原生不加字段，token_id 缺配置时为空字符串。
password 使用 UTF-8 → RSA PKCS#1 v1.5 → base64，使用登录公钥；nil 省略，空串加密仍为空串。
成功包的 username/password 均显式为空串；高层无密码 signup 默认同样发送，
低层 model 保留 None 表示省略的语义，不从模板继承历史用户名或密码。
apply 不重复添加 email，不携带 email_code 或 serial_number。
请求使用 snake_case，响应使用 userTicket/serialNumber 等 camelCase，不能混写。

risk 响应 data.isSignup 决定注册或登录。老用户另受 hasPassword 与密码登录开关影响。
isNormal 是存储字段，不是有效 userTicket 的额外通行门槛。
验证码结果按实际挑战状态提供；现有证据不支持“每次 risk 前必须先做 yoda”。

## 公共 body 与 header

公共 body 包含 device_id、device_type、tk_context_plain 和 fingerprint。
**device_id 来自 IDFA/advertisingIdentifier（与 B 指纹 I18 相符），不是 IDFV/I20。**
设备注册、a7/a8、OneID 的下发与回填关系见 `REGISTRATION_ID_STAGES.md`。
当前区域、SDK 配置和对应本次会话的 fingerprint 需由调用方提供。

公共请求层使用区域 passportHostUrl 与 query 参数；添加 sailor-net-flag，按配置添加
incog-token/incog-accountid。mtgsig 等其他 header 由全局签名/网络插件层补齐，
须在最终 URL、body 和当前设备状态确定后重新签名。
完整包 risk/apply/submit 各含不同的非空 incog-token；当前协议未实现该 SDK 的生成/刷新。
配置只对 BR 启用 Incognia，旧原生 HK risk 同样不带该头，不能把当前 HK 缺该值视为已证实的错误。
新的有效 userTicket 仍须从当前请求的成功 risk 响应取得，不复用捕获凭据。

## 可复现实现

```sh
python3 -m unittest tests.test_login_protocol tests.test_login_execution -v
python3 keeta_offline_flow.py --capture 新机之后尝试登录.chlsj \
  --profile current_profile.json --identity current_identity.json
```

第二条默认仅构造计划。设备前置执行器按捕获顺序保留重复步骤，OneID、newreg、
info/report、v5/sign 等响应逐次回填；具体执行选项与 envelope 输入见
[REGISTRATION_FLOW](../REGISTRATION_FLOW.md)。`keeta_login.py` 已接入恢复模块；显式 overrides 仍兼容旧 camelCase 入参，
发送前统一转换成 snake_case。历史 ticket、serial、code 不再自动复用。

## 验证边界

- 请求字段、form 公共层、risk 和 apply 响应路径已有完整静态链，模块测试可离线执行。
- 两份真实抓包 risk 均为 HTTP 200 / `101135 user_risk_deny`，登录 confirm 为 HTTP 403。
- HTTP 403 单独不能证明地理原因；risk 拒绝单独不能证明某个硬件字段或新机工具能解决。
- 离线密码模块可构造请求，服务端设备身份、风控票据、发码序号和验证码仍按真实响应推进。
- 当前尚不能声称无需任何额外动态状态即可完成全链注册，亦不能把旧抓包票据当本次新下发。

不再把成功抓包作为恢复字段的唯一前提；成功运行验证则仍需观察真实请求与响应。
详细证据、已覆盖范围和剩余接口见 [LOGIN_PROTOCOL_STATIC](../LOGIN_PROTOCOL_STATIC.md)、`OFFLINE_CHAIN_AUDIT.md`。

## 执行器兼容变化

`plan_signup_flow()` 保留既有参数，新增 signup、username、password、encrypted_password、
common。signup=None 仅为离线计划按模板选择分支；`run_one()` 以当前 risk 的 isSignup 决定。
没有 apply/submit 抓包时，从 risk 的区域上下文和已恢复路径构造，不再报缺模板。
缺 user_ticket、serial_number 或 email_code 时在相应阶段返回明确错误，不继承旧值。

`plan_segment()` / `send()` 统一使用最终 model 表单再签名。显式 password 入参为明文；
调用方提供的 RSA 密文须用 encrypted_password，模板自带 password 不再继承。二者不可同时传。
公共 device_id 若未覆盖，可保留模板的 advertising ID；不会用 idfv 代替。
这仍要求调用方提供当前设备上下文，不能将历史公共数据当全新设备数据。

`run_one()` 只在成功 risk/发码响应后推进，错误响应不会读邮箱或提交；发码响应 email
还须匹配本邮箱。`parse_submit_response()` 严格接受顶层 user.token/id/idStr/email，
拒绝伪成功标志、嵌套 token、账户邮箱不符、ID 冲突及显式失败响应。
apply/submit 允许本包证实的显示模式：原邮箱前三字符加 `***@完整域名`；
`email` 保留完整原始接码地址，响应显示值另存 `display_email`，并标记 `email_match=masked`。
掩码不是唯一身份校验，仍需本次 risk ticket、apply serial 与验证码提交的状态关联。
默认不需要指定 token_path；兼容路径也必须等于已验证的 user.token。
执行过程中不打印票据、验证码或账号 token。

`tools/login_session_probe.py` 将账户 token 单独存入 0600 的 `account-session.json`，
普通 response/event 工件遮盖 token；设备 identity/profile 不写入账户凭据。
`account_token_received=true` 表示响应中的账户已通过上述检查；
`account_token_verified=false` 明确表示未用该 token 请求后续账户接口验收。
本轮协议与执行测试使用合成响应并禁用 socket；另对真实成功包在内存中验证表单逐字节
相等和账户解析，不发送旧验证码或票据。
