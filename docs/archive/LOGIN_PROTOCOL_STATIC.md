# 邮箱协议的静态恢复证据

> 历史研究资料，来源 `codex/keeta-project@6197c528`；保留当时的观测与未完成项，不代表新项目当前状态。当前规则见 [字段状态](../MTGSIG_FIELDS_STATUS.md)，复跑入口及已修正结论见 [离线研究指南](../research/OFFLINE_RESEARCH.md)。文中的旧 `dump/`、抓包及设备路径仅作证据索引，原材料未随仓库发布。

本轮从 `dump/Keeta.dec` 恢复请求构造、响应读取与密码加密，产出
`mtgsig/login_protocol.py`。没有发送网络请求、邮件或手机操作。
请求格式已经有明确静态证据；尚无成功发码或登录返回 token 的运行验证。

## 样本与重现

- 样本：arm64 iOS `dump/Keeta.dec`，Mach-O 基址 `0x100000000`。
- SHA-256：`0900cac89f75fc4f75279c708785bf2c7a03c228301a8e75ce62f93e3ad88488`。
- 下列地址均为 module RVA；工具按 Mach-O 段映射读取，并未假定任意文件偏移等于 RVA。
- `tools/inspect_login_static.py` 基于 LIEF 和 Capstone，输出 `dump/login_protocol/*.asm`。
- `dump/login_protocol/methods.json` 保存样本 hash 与解析的方法表。
- 注释中的寄存器常量只用于辅助阅读；调用与字段关系以反汇编上下文为准。

```sh
python3 tools/inspect_login_static.py 0x2b5edf0 0x2b5eee0 0x2b5ef50 0x2b5f088 0x2b8e7b4
python3 -m unittest tests.test_login_protocol -v
```

工具解析 classlist 的绝对 method lists，尚未自动遍历 category lists。密码 category 的
地址通过独立遍历确认，已输出对应反汇编；外部 classrefs 可能无名称注释。

## 请求字段：snake_case，与响应属性名不同

路径前缀均为 `/api/emaillogin/v1/`，方法均为 POST。
以下列出 model 自己写入的字段；公共层字段另见下节。

| 路径尾部 | model 字段 | 构造器 RVA |
|---|---|---|
| userriskcheck | email、request_code、response_code、token_id | `0x2b8e7b4` |
| emailloginapply | user_ticket | `0x2b5eee0` |
| emailsignupapply | user_ticket、username、password | `0x2b5edf0` |
| emaillogin | user_ticket、email_code、serial_number、request_code、response_code | `0x2b5f088` |
| emailsignup | user_ticket、username、password、email_code、serial_number | `0x2b5ef50` |

原生 safe-set 不加入 nil 值，因此缺失 request_code/response_code 不等于显式空串。
risk 的 token_id 配置缺失会写空字符串。password 为下面说明的 RSA 密文。
注册数据对象虽然持有 email，apply 构造器不再次将 email 写进 body；
不能复用完整 risk 表单、仅替换 URL 后就当成 apply。

`0x2b5f164` 根据 verifyType 选择 apply 路径：4 是 emailloginapply，其他分支为
emailsignupapply。这两条路径由 `soa_postPassportPath:parameters:finished:` 发出。

## 公共字段、请求体编码和 header

`0x2b462bc` 将 model parameters 交给 body，URL parameters 为 nil，经
`0x2b462cc`、`0x2b462dc`、`0x2b462e8` 进入 `0x2b462f0`。该方法组合区域 passportHostUrl
与 path，分别生成公共 body 和 query，再调用 postToURL 系列方法，timeout=10 秒。

`0x2b46c88` 的公共 body 添加：

- idfa 为 NSString 时，device_id=idfa、device_type=字符串 `"3"`。
- tk_context_plain 来自区域配置，并受 token 标准化 Horn 开关控制。
- fingerprint 在 SAKBaseModel 的 corpse/公共 body assembly 阶段加入。

`0x2b46d68` 的 idfa getter 通过 advertisingIdentifier → UUIDString 获取值。
所以 passport 的 device_id 是 IDFA/advertising ID，不能直接用 IDFV。
真实新机包也满足 form.device_id=B.I18，而 newreg.deviceid=OneID.idfv=B.I20，二者不同。

Content-Type 的证据链：

1. SAKBaseModel.init `0x2a045b0` 将 parameterEncoding（对象偏移 `0x14`）初始化为 0。
2. `0x2a083c4` getter 与 `0x2a0557c` assembleRequestURL 将其传给 request 构造。
3. `0x2b3f57c` 继续传给 body serializer `0x2b3e654`。
4. serializer 的 encoding=0 分支是 `application/x-www-form-urlencoded; charset=%@`；
   1、2、3 分别为 JSON、plist、multipart。URL key/value 连接见 `0x2b3f054`。

原生 NSString encoding=4 对应 UTF-8。post 包装层的 `dataEncoding=3` 不能替代上述
parameterEncoding 推断。模块使用标准 urllib.urlencode；尚未逐字符验证原生空格是否
编码成 `%20` 或 `+`，所以只声称字段和编码语义一致，不声称完整请求文本逐字节对拍。

`0x2b468cc` 公共 query 包含 uuid、lang、version_name、sdk_version、joinkey、
package_name、配置的 i18n 项、appId、cityId、region，以及可选 registerRegion、
开关控制的 passport_lat/passport_lng、risk_cost_id。该样本的 passport sdk_version
常量是 `0.3.63-i18n`，不能拿它替代 app 或 SAKGuard 版本。

`0x2b46708` 添加默认 `sailor-net-flag: MTPT.Passport`，并在配置/开关允许时添加
incog-token 和 incog-accountid。`0x2b474f0` beforeSend block 调用此方法。
mtgsig、pragma、uuid 等其他 header 来自全局网络插件层；这些不是本构造器的完整列表。
`passport_headers()` 保留 caller 当前 header，剔除旧签名、Content-Length、Host，设置 form
Content-Type；调用方须在最终 URL/body 准备好后重新签名。

passportHostUrl `0x2b5bc50` 来自区域 Compass 配置，fallback 为
`https://passport.mykeeta.com/api`，不是固定要求某个地区域名。

## 响应与状态分支

risk completion `0x2b8ec20` 从顶层 data 构建 SOAUserRiskCheckSuccessResponse；
顶层 error 则进入错误模型。predicateDictionary `0x2b8f214` 映射：

| 响应 JSON 路径 | ObjC property | Python 模块输出 |
|---|---|---|
| data.userTicket | userTicket | user_ticket |
| data.isSignup | isSignUp | is_signup |
| data.isNormal | isNormal | is_normal |
| data.hasPassword | hasPassword | has_password |

这些属性 optional，缺失 BOOL 对应 false。manager `0x2b8c480` 要求 response 存在且
userTicket.length>0 才继续；isSignup=true 走注册页，否则按 hasPassword 与
isEmailSupportPawLogin 配置选择密码页或验证码页。isNormal 被保存到 storage，
它不是阻止已有票据继续的条件。

`0x2b8c208` 可复用同 email 且年龄小于 600 秒的 ticket（double 常量 RVA `0x35c3558`）。
本模块没有实现这个缓存，调用方可选择每次重新 risk，不能无期限复用历史票据。

apply completion `0x2b5f1dc` 直接读取 data.email 和 data.serialNumber；
两者通过 isNSStringNotNull 才回调成功。`0x2b5c4a0` 的检查仅确认非 nil 且 NSString，
不检查长度。Python parser 额外要求非空，是执行器的保守门槛，不是原生检查原样翻译。

模块 parser 只接受对应 data 路径，不递归搜 ticket，不把错误消息里出现的 serialNumber
当成功。HTTP 必须为 2xx；显式 error/success=false/非零 code 拒绝推进。
原生 callback 不强制 code=0，模块也允许缺失 code；若 gateway 显式提供 code，
模块保守仅接受整数 0。这是附加校验，不冒称原生响应一定有 code。
登录/注册完成后的 token 路径尚未在本轮恢复或运行验证。

## 密码 RSA

NSString `soa_rsaEncryptWithPublicKey:` (`0x2b462b8`) 尾调 category `0x2a72234`：
先 UTF-8 转 NSData，经 NSData category `0x2a71b18` RSA 加密，最后 standard base64。
NSData 按 RSA_size-11 切块；CIPRSAUtil `0x2a70a14` 将 padding=1 传入本地
RSA_public_encrypt wrapper `0x88a578`，即 PKCS#1 v1.5。

- 登录公开 SPKI 位于 CFString RVA `0x431f420`，2048 位，e=65537，每块最多 245 字节。
- 它是密码专用公开密钥，与 A envelope 公钥不同。
- 多块 RSA 密文连接后统一 base64；不是逐块 base64 再连接。
- 空 NSString 会进入零次分块循环，产生空密文与空 base64；nil 保持 nil，safe-set 不加字段。
- 模块 `encrypt_password()` 保留以上空值边界。

已用 Python 生成的临时 RSA 密钥对检查 UTF-8、分块、私钥解密、独立 modular exponent
恢复的 type-2 padding，以及内置公钥尺寸。尚无原生 synthetic password 加密对拍，
所以当前结论为完整静态链恢复加本地密码实现验证，不是设备输出逐字节验证。
PKCS#1 v1.5 自带随机填充，相同明文不能直接比较不同调用的 base64 是否相等。

## 已验证与仍缺失

`tests/test_login_protocol.py` 的 10 项测试禁止创建 socket，验证真实两份 risk 抓包字段集
重建、真实拒绝响应不推进、apply/login/signup 参数区别、RSA 边界、公共字段隔离、
header 更新、风险票据与发码响应路径和错误类型。

两个历史抓包都没有成功发码：旧包索引 801、新机包索引 628 的 userriskcheck 均为
HTTP 200 / `101135 user_risk_deny`；前一条登录 confirm 为 HTTP 403。
静态恢复已经消除了“必须等待成功抓包才能知道 apply 字段”的依赖；实际服务端放行、
密码分支运行、serialNumber 下发与最终 token 仍需独立验证。


## 执行器接入

`keeta_login.py` 已使用该模块构造 risk/apply/submit。旧 overrides 的 camelCase 名仅在
Python 入参边界兼容转换，wire 始终 snake_case。load_templates 采用精确路径匹配，
修复 emailsignupapply 曾被误认为 emailsignup 模板的问题。无后续模板时复用 risk 的
区域 URL/query/header 上下文并使用恢复路径；无本次 ticket/serial/code 则停止。

`tests/test_login_execution.py` 的 7 项测试覆盖路径误匹配、过时状态不继承、最终 body
签名、真实响应字段分支以及失败时不会读邮箱/继续提交。全部禁止 socket，mailbox 亦为
注入结果。最终账号 token 的模型未恢复，所以执行器仅接受显式、已经验证的 token_path；
不再递归搜索响应中任意 token 当成功证据。


## seq184 后的离线发码接续

`mtgsig/email_flow.py` 通过同一个 FullSigner 和主请求构造器执行登录确认、risk及apply。
risk 成功返回的 isSignup 决定 emailsignupapply/emailloginapply；不继承捕获邮箱或旧票据。
每步独立更新 B 指纹时间和签名，apply 的全部模型字段重新构造；服务器返回本邮箱和
serialNumber 才记录 apply 响应确认。该标志不代表已经收到邮件或完成账号注册。

`tools/login_session_probe.py` 将本次输入、请求、响应与消费后的计数保存为0600工件。
缺邮箱时允许生成不可发送的准备目录。默认一次最多执行 confirm/risk/apply 三个请求；
显式增加 `--mail` 后，apply 前保存邮箱 UID 快照，apply 成功且邮箱/serialNumber 匹配后
只取快照高水位以后的新邮件，再提交 email login/signup，最多四个请求。它不操作手机、
不注册新设备身份，也不自动重试。邮箱凭据和验证码不写入控制台，落盘的提交请求隐去
email_code。最终响应结构通过检查只记为 submit_response_confirmed；账号 token 路径
仍未验证，不能据此声称成功登录。

历史准备目录：`dump/registration_session/login_pending_email_01/`，初始身份序号为184。
它可用于第一次试跑；后续邮箱必须使用上一尝试保存的 identity-after.json，失败也保留
已经消耗的计数。以下命令中的 IDENTITY 指向本次可接续的最新身份，不修改原件：

```sh
python3 tools/login_session_probe.py --profile dump/registration_session/login_pending_email_01/profile.json --identity "$IDENTITY" --email "$TEST_EMAIL" --out dump/registration_session/login_live_01 --mail mail.txt --send
```

`tools/login_mail_trials.py` 从明确提供的邮箱配置顺序选择少量账号，默认只生成预览；
`--send` 才执行上述四步。每个邮箱完成 identity-after.json 保存后才准备下一个邮箱，
终端只输出邮箱序号与阶段结果。发布清单包含工具和 fake IMAP 测试，不包含 mail.txt、
当前 profile/identity、抓包或真实响应。

tk_context_plain 静态来源见 LOGIN_CONTEXT.md；45字段说明与快照时间边界见
LOGIN_FINGERPRINT_FIELDS.md；区域语言/GPS输入的明确来源见 REGISTRATION_LOGIN_CONTEXT.md。
无真实 risk/apply 响应前，不将禁网测试视为业务成功。
