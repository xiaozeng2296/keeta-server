# 登录公共参数 tk_context_plain

> 历史研究资料，来源 `codex/keeta-project@6197c528`；保留当时的观测与未完成项，不代表新项目当前状态。当前规则见 [字段状态](../MTGSIG_FIELDS_STATUS.md)，复跑入口及已修正结论见 [离线研究指南](../research/OFFLINE_RESEARCH.md)。文中的旧 `dump/`、抓包及设备路径仅作证据索引，原材料未随仓库发布。

当前 `dump/Keeta.dec` 中，这个字段是配置上下文的标准 Base64 编码，
没有密码加密。地区必须取当前流程的有效地区状态，不能从旧抓包拷贝。

原生构造固定顺序为：

```json
{"a1":"HK","a2":"5","a3":"4"}
```

- `a1`：`SOAAccountUIConfig.shareInstance.region`。
- `a2`：`SOAAccountConfig.tokenPlatform`，当前 App 初始化为字符串 `5`。
- `a3`：`SOAAccountConfig.tokenApp`，当前 App 初始化为字符串 `4`。

先手工拼紧凑字符串，再编码 UTF-8、标准 Base64，最后删除所有 `=`。
不是 URL-safe Base64。原生 `%@` 拼接不做 JSON 字符转义；模块保留该字节行为。
实际调用应传配置中的地区和平台/App 值，不应将任意用户文字作为这些配置。
任一值不是非空字符串时，原生生成空字符串，公共 body 不加这个字段。

HK 的结果为 `eyJhMSI6IkhLIiwiYTIiOiI1IiwiYTMiOiI0In0`。
BR 的结果为 `eyJhMSI6IkJSIiwiYTIiOiI1IiwiYTMiOiI0In0`。

## 静态证据

以下是 Mach-O 相对 image base 的 RVA，聚焦反汇编保存在 `dump/login_context/`。

| 位置 | 行为 |
| --- | --- |
| `0x22828d8` `-[SLHighPriorityLanucher setupAccount]` | `0x2282964/68` 设置 tokenApp=`4`；`0x2282988/8c` 设置 tokenPlatform=`5` |
| `0x228293c/40` → `0x2282944` | 从 CFString RVA `0x4272680` 加载本 App 固定配置并调用 `setTokenID:` |
| `0x2b47178` `-[SAKBaseModel p_configTkContextPlain]` | 从 UIConfig 取 region，调用 context manager |
| `0x2b8a1a8` `getTkContextPlainWithRegion:` | 校验三个非空字符串，固定 keys=`a1,a2,a3`，values=`region,platform,app` |
| `0x2b8a398` `p_getTkContextFromDict:withOrderedKeys:` | `"%@":"%@"`、逗号连接、`{%@}`、UTF-8、base64、删除 padding |
| `0x2b46c88` 公共 body 构造 | `0x2b46d28` 读取 disableTokenStandardization；true 跳过字段 |

原生 manager 只按 region 缓存结果，没有把 platform/app 纳入 cache key。
独立 Python 函数无缓存，按每次显式输入构造；它不模拟更改配置之后的旧缓存行为。

## risk 的 token_id

`SOAAccountConfig.tokenID` 与 `tk_context_plain` 是两个字段。当前 build 在
`setupAccount` 初始化时将二进制中的固定 CFString 写入 tokenID，随后才设置 tokenApp
与 tokenPlatform；该值不依赖邮箱、设备注册响应或服务端下发，也不是账号登录凭据。
`SOAAccountManager.p_saveCommonInfoForKNB` 将配置同步给 `Channel.Account.tokenID`，risk 构造器从该配置 getter
读取后写入 `token_id`。缺配置写空串只是原生兜底行为，不代表服务端接受空值。

`context_profile_fields()` 在显式 `login_context_inputs` 指定当前 build 的
platform=`5`、app=`4` 时，为缺失或空的 token_id 填入该原生 App 配置；显式非空
自定义值保留。未提供这些配置、或选择其他 platform/App 时不自动套用。这个修复
同时作用于之前保存了空 token_id 的 profile，不需要从抓包复制会话字段。

已在本地仅比较值而不输出字面量，确认该常量与旧包第 801 项、新机包第 628 项
userriskcheck 的 token_id 完全相等。其效果仍需真实响应单独验证，静态一致不能
视为 risk 放行、收到验证码或登录成功。

## Horn 开关

来源是 `PassportOverseaRollbackSwitch_iOS` 的 `disableTokenStandardization`。
`SOAHornManager init` (`0x2b612b4`) 未写该 ivar，ObjC 零初始化使初始值为 false。
`resolveRollbackSwitchConfigWithResult:` (`0x2b61a34`) 解析非空配置字符串后，
通过 `cipf_boolForKey:defaultValue:` 读取该 key，默认参数也是 false。
空配置字符串不更新已有状态。

`registerHorn` (`0x2b61378`) 先读取此 type 的缓存，再注册异步 callback。
回调 `0x2b620c8` 仅在 enabled 标志为真且字符串非空时调用 rollback resolver。
它不同于普通登录配置 `PassportOverseaConfig_iOS`。

历史 `新机之后尝试登录.chlsj` 第 38 项是 `h-eu.mykeeta.com/horn_ios/mergeRequest`：
响应 `PassportOverseaRollbackSwitch_iOS.data` 为字典，未包含
`disableTokenStandardization`，故该份历史配置适用 false 默认。
这只证明历史配置布局，不能声称新的协议 session 已获取实时 Horn。

## 使用与验证

```python
from mtgsig.login_context import context_body_fields

common.update(context_body_fields(current_region,
    disable_token_standardization=current_resolved_horn_switch))
```

未获取 Horn 时可以使用有静态证据的初始 false，但流程状态应记录默认来源，
不能把它标成实时服务端配置。函数要求开关为 bool，避免字符串 `"false"` 误判。
函数只返回当前应有的字段；调用方每次应从新 body 构造，避免 disabled 时保留旧字段。

`tests/test_login_context.py` 禁止创建网络 socket，验证 HK/BR 精确向量、
UTF-8/原生不转义行为、空值省略、开关，以及两份原始抓包的相同字段。
抓包对照只验证 constructor 的线格式，不等于服务端接受新登录流程。
