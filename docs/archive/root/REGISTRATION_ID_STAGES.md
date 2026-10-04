# 注册阶段的 a7 / a8：本地候选值与服务端值

> 历史研究资料，来源 `codex/keeta-project@6197c528`；当前规则见 [字段状态](../../MTGSIG_FIELDS_STATUS.md)，复跑入口及已修正结论见 [离线研究指南](../../research/OFFLINE_RESEARCH.md)。旧抓包、身份与运行路径仅作证据索引，原材料未随仓库发布。

`a7`、`a8` 不是从启动到登录始终不变的单个值。首次启动时，SDK 先生成
本地候选值并用它完成注册请求；服务端响应回来后，SDK 才把服务端值写入后续
`mtgsig`。因此从单个首请求样本直接取 `a7/a8`，不能证明它们已经是注册后的值。

## 已核对的真实时序

以下值只展示前缀，完整值保存在对应 Charles 抓包中：

| 抓包 | 请求阶段 | 请求中的 a7 | 响应字段 | 后续请求中的 a7 |
|---|---|---|---|---|
| `从app初次打开到登录被拦截.chlsj` | `/fingerprint/v1/info/report` | `aMp7qV2t...`（本地生成） | `data.result=CN0Z+NDr...` | bio/device-info 使用 `CN0Z+NDr...` |
| `新机之后尝试登录.chlsj` | `/fingerprint/v1/info/report` | `plPEUuui...`（本地生成） | `data.result=9rb5wym...` | bio/device-info 使用 `9rb5wym...` |

`data.result` 就是这次注册返回的 XID；设备落盘的
`.mtg_dfpid_com.sankuai.meituan` 中的 `xid` 对应这个服务端结果。它不是
首次 `main(1)`/`main(2)` 生成的本地候选值。

`a8` 同样有两个阶段：

| 抓包 | 先发请求的 a8 | `/v5/sign` 响应 `data.dfp` | 后续 `/fingerprint/v1/info/report` 的 a8 |
|---|---|---|---|
| `新机之后尝试登录.chlsj` | `dad7b0fd...`（本地 dfpID） | `aee320e9...` | `aee320e9...` |
| `从app初次打开到登录被拦截.chlsj` | `d3ec0707...` | `d3ec0707...` | `d3ec0707...` |

在 `新机之后尝试登录.chlsj` 中，`/v5/sign` 先于 fingerprint info，故同一轮里可以直接看到
本地 a8 与响应 dfp 的切换。a8 的有效服务端值是 `/v5/sign` 返回的 `dfp`，
而不是假定本地缓存值永远等于它。

## 设备身份档约定

`farm.fullsign.provision_identity()` 保留首个样本的值，并支持显式注册结果：

```json
{
  "mtgsig": {"a7": "LOCAL-XID", "a8": "LOCAL-DFP-ID", "...": "..."},
  "registration": {"xid": "SERVER-XID", "dfp": "SERVER-DFP"}
}
```

生成的身份档会同时保存：

- `a7_captured`：样本请求实际使用的值；`a7_local_xid` 单独保留注册切换前的本地候选；
- `a7_server_xid` / `xid`：`fingerprint/v1/info/report` 的明确响应值；
- `a8_captured`：样本请求实际使用的值；`a8_local_dfp` 单独保留注册切换前的本地候选；
- `a8_server_dfp` / `dfp`：`v5/sign` 的明确响应值。

`FullSigner` 只有在身份档明确提供 `a7_server_xid`/`xid`、
`a8_server_dfp`/`dfp` 时才优先使用服务端值；没有响应证据时保留样本值，
不会从本地 a7/a8 猜测 XID 或 DFP。

## 执行期间回填

服务端响应可以在同一 signer 生命周期内应用，不需要重新加载身份档：

```python
changed = signer.apply_registration_response(
    "/fingerprint/v1/info/report",
    {"code": 0, "data": {"result": "SERVER-XID"}},
    http_status=200,
)
```

`mtgsig.registration_state` 只接受已知端点的确切字段、成功 HTTP、整数
`code=0` 和非空有效字符串。info report 同步 `a7`、`a7_server_xid`、`xid`；
v5/sign 同步 `a8`、`a8_server_dfp`、`dfp`。失败返回空 patch，身份保持原状。
已有 local 字段不会覆盖；首次有实际值切换且没有旧服务端标记时，才保存切换前
候选。如果当前值已等于响应，不因这次响应把它重新标注为本地候选。

`FullSigner` 同步 `dev` 和有效 a7/a8，下一次签名重新生成完整 payload 与 a2。
`OfflineSigner` 同时更新 `mt` 与 `pay_template`，避免请求使用新身份而 HMAC
仍签旧字段；身份状态的附加字段不会混入线上 mtgsig。

`keeta_offline_flow.execute_offline_flow()` 按“构造请求 → sender → 验证响应 →
回填身份 → 签下一请求”执行。`send(request)` 返回 `(http_status, response_json)`，
因此网络执行和离线响应回放共用同一状态处理。请求不完整或响应失败即停；
CLI 的 `--send --identity identity.json` 会在结束时保存计数器和已验证的服务端值。

## 抓包顺序与验证范围

CLI 默认 `--order capture`，通过 `load_capture_steps()` 保留筛选接口的请求顺序、
重复上报和对应模板。逻辑列表仅由 `--order logical` 显式选择；两个注册响应
互相独立，不要求固定的 info/sign 顺序：

| 抓包 | 筛选请求数 | 注册端点的先后 |
|---|---:|---|
| `从app初次打开到登录被拦截.chlsj` | 13 | info report（索引 96）→ v5/sign（100） |
| `新机之后尝试登录.chlsj` | 13 | 先有两次 OneID（7/10），随后 v5/sign（16）→ info report（65） |

`tests/test_registration_execution.py` 用真实 FullSigner 加合成身份检查后续 a7/a8
切换、完整 payload 的 a2 和错误停止，并在禁止 socket 的情况下读取上述抓包，
核对顺序、重复步骤并注入已有注册响应。测试通过表示本地实现与这些样本相符，
不是新设备注册已在业务网络成功，也不补足设备画像的未知采集语义或后续风控票据。
A envelope 密码链的原生对拍已单独完成，见 `docs/ENVELOPE_SDK.md`。

OneID 状态由 `mtgsig/oneid.py` 分开管理：`requiredId=4` 响应的 `data.unionId`
更新 `csecuuid/uuid`，`requiredId=1` 更新 `unionid`。OneID 的 localId/sessionId
也独立命名，不能与上述 SAKGuard 本地 xid/dfp 或 localid 混用。
