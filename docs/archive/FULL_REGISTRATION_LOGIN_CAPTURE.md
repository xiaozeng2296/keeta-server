# 完整新设备注册登录抓包结论

> 历史研究资料，来源 `codex/keeta-project@6197c528`；保留当时的观测与未完成项，不代表新项目当前状态。当前规则见 [字段状态](../MTGSIG_FIELDS_STATUS.md)，复跑入口及已修正结论见 [离线研究指南](../research/OFFLINE_RESEARCH.md)。文中的旧 `dump/`、抓包及设备路径仅作证据索引，原材料未随仓库发布。

`完整版新设备注册登录.chlsj` 确实补齐了原生成功链路：初始设备身份、区域选择、
服务端 DFP/XID 下发、成功 risk、发码、4 位验证码注册，以及后续已登录接口。
共 778 条记录、83,181,326 字节；SHA256 为
`5f218afcfe01a3a1acedee5938753ccf2528e4d2d8603c26553c03d39153013a`。
本轮只在本地解析和验证，未重放业务请求、访问邮箱或操作手机。

索引以下均为零基索引。真实业务主机优先读取 HTTP/2 `:authority`，其次 HTTP `Host`，
最后才回退 Charles 外层 `host`；后者可能代表被复用的连接。

## 已闭合的链路

| 阶段 | 包内证据 | 状态关系 |
|---|---|---|
| 初始 OneID | #0 / #1，requiredId=1 / 4 | 同一 IDFV/localId/sessionId 的并发注册；两个响应分别用于 unionid / csecuuid |
| 初始推送与指纹 | #9 newreg、#14 info/report、#36 v5/sign | 得到 P1、XID1、DFP1，后续签名使用服务器身份 |
| 选区 | #53 Compass、#65服务区、#117 currentLocalInfo | GG→BR，cityId=102302389，districtId=102317211 |
| BR 再注册 | #132 v5/sign、#185 info/report、#201 newreg | DFP 仍为 DFP1；XID 变为 XID2、push token 变为 P2 |
| 设备上报 | #183/#342 scfg、#184 bio、#270/#431 device-info | 有真实成功响应；并非每个请求都是串行依赖 |
| 语言更新 | #321 currentLocalInfo | BR 城市/区保持；locale/lang 由 zh 变 en |
| 登录风控 | #585 userriskcheck | 返回本次 userTicket，isSignup=true、hasPassword=false |
| 发码 | #589 emailsignupapply | 使用该 userTicket，返回 serialNumber 和显示邮箱 |
| 提交 | #601 emailsignup | 同一 userTicket、正确 serialNumber、4 位验证码，返回 user.token/id |
| 登录验收 | #605 userRedDot、#606账户状态 | 使用 #601 的 token，HTTP200/code0 |

risk→apply→submit 三步的实际 authority 都是 `passport-eu.mykeeta.com`。
三条请求使用同一个服务端 DFP1 和更新后的 XID2；票据与序号逐项精确相等。
之后共 17 个请求使用返回的账户 token。这证明本次原生会话成功，
不等于此前序号 193 的 HK 协议身份已经通过登录风控。

```mermaid
flowchart LR
    A[本地身份与 OneID] --> B[初次注册：DFP1 / XID1]
    B --> C[GG 选择为 BR]
    C --> D[再次注册：DFP1 / XID2]
    D --> E[585 risk：新 userTicket]
    E --> F[589 apply：serialNumber]
    F --> G[601 submit：账户 token]
    G --> H[605 / 606：账户接口成功]
```

该图表示状态阶段，不表示 App 每条 HTTP 请求都严格串行。
例如 OneID 两条请求并发；risk 在 confirmProtocol 响应完成前已经发送。
不能把 newreg/info/sign 的某次观察顺序提升为唯一合法顺序。

## 对此前判断的修正

1. **userTicket 来源已找到。** 前一份 229 条成功片段没有的 risk，现在在 #585 完整出现。
   它由服务器当次返回，不是从 a9、DFP 或本地字段计算出来的。
2. **没有换到 fooddelivery 登录域。** 外层 flow.host 是 fooddelivery-eu，
   但请求 authority 是 passport-eu，符合 Compass 的 Passport.url。
3. **响应邮箱是显示值。** apply 和 submit 返回 `原邮箱前3字符 + *** + @完整域名`；
   三个星号不表示原邮箱剩余字符数。前一轮“与当前邮箱匹配”的对拍实际只验证
   apply/submit 两个显示值一致，没有核对原始收件地址，这次已补正。
4. **同一会话的 DFP 确实复用。** #36 与 #132 两次下发完全相同；XID 却更新。
   这不等于已恢复“相近设备”的服务端聚类规则，成功与当前协议的同型号样本 DFP 仍不同。
5. **Incognia 分地区启用。** #12 配置为 enable=true、regions=[BR]。
   旧 HK 失败包也有同样配置，原生 HK risk 本来不带 incog-token；不能把缺头直接归因成拒绝原因。

## 本轮修复与离线验证

- 修复 Charles 导入与请求构造的 authority 优先级，包括 HTTP/1 Host 回退；最终 Host
  与选区后的 URL 同步。离线构造与签名使用同一个业务目标。
- apply/submit 只接受已观察的受限邮箱显示模式或完整地址匹配；完整收件地址继续存入 email，
  脱敏展示另存 display_email 和 email_match=masked。邮箱快照和收码不会使用星号地址。
- mask 兼容性不证明邮箱唯一性，账户状态仍关联本次 risk→ticket→apply→serial→验证码提交。
  既有 token、用户 ID、错误响应检查保留；没有从历史抓包拿票据或验证码推进。
- 新包的 risk/apply/submit 三种表单均与原请求逐字节对拍一致；修复后，
  三步响应解析都接受真实数据，并保留原始邮箱。
- `login_steps()` 可以从新包选到 #584/#585；通用 capture loader 保留重复上报，
  到 risk 为止提取 24 条已支持的核心请求。
- 本地全量 341 项测试通过；远端发布暂存目录同样 341 项通过，线上 HTTP 加解密验收通过。
  修复发布为 `20260929T033842Z-f2977794`，回执为
  `rpc/.state/20260929T033850Z-b5999d.json`。发布不发送业务登录请求；本报告及分项分析
  和审计脚本保存在本地工作区，不作为 RPC 运行依赖发布。

当前加解密验收：

| 项目 | 结果 |
|---|---|
| 原生 a5 | 93/93 成功，default 配置 |
| 原生 a9 | 9/9 种密文通过 padding/CRC/zlib，均为 twofish |
| B fingerprint | 16/16 份成功，每份 45 项 |
| scfg | 两次请求和响应配置均可离线解密 |
| 完整 a2 | 92/93 一致；risk/apply/submit 三步全部一致 |
| A-envelope | 9 份共用同一 RSA part1，但现有会话密钥均不匹配，正文尚不可解 |

唯一 a2 差异是登录后的 #766 app bio（49,436 字节正文），不在发码前。
该条的后半轮运算可由捕获前半与独立解出的 a5.b2 复现；前半输入差异仍需查明。
不能把 92/93 报成全部签名已逐字节通过。

## 尚未闭合的实现范围

- BR 成功链的 incog-token 仍没有本地生成/刷新实现。全包 52 次携带、44 个值，
  是 556 字符 URL-safe Base64、417 字节二进制。部分并行请求共享值，登录三步则各不相同；
  不能说它是永久常量，也不能据此断定每请求必须生成新值。未找到可见响应直接下发它。
- 外部抓包 A-envelope 的会话材料没有因“完整包”自动变成明文；缺该材料限制成功设备
  明文画像的完整对照。当前程序为自己的会话生成 A-envelope 是另一项已实现能力。
- `tools/registration_session_probe.py` 仍是旧实验专用入口，要求初始三步严格为
  sign→newreg→info。给它这份新包会明确报 `capture initial registration order differs`。
  通用 loader 可以读取新顺序，不表示该专用实验入口已适配全部新包。
- 目前协议画像仍是手机采样与本次 ID 的组合，不是这份成功包的完整新机明文。
  其与成功 risk 的 B 值有 33/45 项相同；具体差异已列在设备报告中。
- 本轮没有新发验证码、提交登录或更换运行身份；不能以离线回归通过宣称纯协议全链验收成功。

## 可复核工件

机器可读脱敏审计：`dump/registration_chain_audit/full_success_01/audit-final.json`。
独立重新生成（输出文件必须尚不存在）：

```sh
python3 tools/audit_full_registration_capture.py \
  '完整版新设备注册登录.chlsj' \
  --out dump/registration_chain_audit/full_success_review/audit.json
```

该工具只读取本地包，输出路径、字段名、长度、布尔关联和匹配数量，不导出认证值。
原始抓包保留不变，派生审计文件权限 0600。

详细分项：

- [FULL_CAPTURE_LOGIN_CHAIN](FULL_CAPTURE_LOGIN_CHAIN.md)：票据、时序、真实 authority、脱敏邮箱与构建器对拍。
- [FULL_CAPTURE_DEVICE_CHAIN](FULL_CAPTURE_DEVICE_CHAIN.md)：OneID/DFP/XID 生命周期、采样字段、解密范围与异常观测。
- `docs/FULL_CAPTURE_INCOG.md`：地区开关、出现时序、格式、复用情况和来源检索。
