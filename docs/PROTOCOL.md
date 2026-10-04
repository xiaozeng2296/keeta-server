# 协议实现与 RPC 使用

本页汇总 2026-09-30 当前代码与已有验证记录，并补充 2026-10-01 原生观察。项目已实现支持配置下的离线 mtgsig 签名、a5/a9 编解码及多种指纹格式处理；完整设备采集、SDK 动态配置解析和服务端身份分配仍有边界。逐字段状态见 [a0–a10 恢复矩阵](MTGSIG_FIELDS_STATUS.md)，采集面板操作见 [运行说明](OPERATIONS.md)。

2026-10-01 原生补充：a3 的 provider 配置成员、a10 的启动随机初始化及当前 x0 的常量写入已定位并观察验证。版本检测、抓包差异审计与真机对拍命令见 [协议升级流程](PROTOCOL_UPDATE.md)。

同日续证：a3/salt 来自 Horn 动态配置，`config` 命令可按响应结束时间核对后续请求，存储和 provider 生效另用 `native/audit` 验证。a6 的部分状态已追到开发团队/PIC 资源绑定、资源完整性与兼容性；不是设备唯一标识。具体证据和未验证分支见 [原生字段观察](research/NATIVE_FIELDS_20261001.md)。

配置生命周期工具 `observe-config` 默认被动，显式 `--refresh` 才发起一次 SDK 配置刷新。它分别记录 Horn HTTP 结果、回调写入和 provider 加载；刷新路径的 304/source=4 未触发回调，正常启动的 304/source=5 则有成功回调和同值写入。该启动中 provider 20→25 发生在回调之前，之后未见重载，不能把收到响应或写入返回当作新配置已激活。异常中断会保存已收到的部分事件，详见升级流程。

## 实现入口

| 组件 | 当前代码 | 职责 |
|---|---|---|
| 完整签名器 | `farm/fullsign.py` | 从身份与采集观察构造 mtgsig，推进签名序号并保存状态 |
| a2 / a5 | `keeta_a2.py`、`mtgsig/mtg_crypto.py` | canonical 请求签名、表变换、a5 压缩与加解密 |
| a9 | `mtgsig/a9_codec.py`、`mtgsig/a9_cli.py` | 严格验证、解码、重新编码及命令行入口 |
| 采集缓存 | `mtgsig/collection_cache.py` | 从已有快照续接周期缓存，联动 a5/a9 |
| SDK envelope / corpse | `mtgsig/envelope_codec.py`、`mtgsig/corpse_codec.py` | 外层信封与 m-series 字段变换 |
| 身份与注册状态 | `mtgsig/local_identity.py`、`mtgsig/bootstrap_identity.py`、`mtgsig/registration_state.py` | 本地候选 a7/a8 及成功响应回填 |
| 注册 / 登录协议 | `keeta_offline_flow.py`、`mtgsig/login_protocol.py` | 按捕获时序构造请求、解析响应与更新状态 |
| Incognia | `mtgsig/incognia_token.py`、`mtgsig/incognia_state.py` | 已观察 token 格式与显式安装/请求状态 |
| HTTP RPC | `keeta_rpc.py` | 为本地算法提供 HTTP 接口 |

路径以项目根目录为基准。静态表和发布资源以 `rpc/deploy.py`、`rpc/remote_update.py` 的当前清单为准；不能仅复制一个签名脚本就认为依赖完整。

## 签名与状态的边界

- `a2` 的完整 16 字节计算链已实现，需要准确的 URL、body 字节、SDK 配置和计数。当前 SDK 纳入 Body UTF-8 的前 16,200 字节，canonical URL 和签名 payload 保持完整；实际 HTTP Body 不截断。重排 JSON 或改变 URL 编码可能改变签名输入。
- `a1` 是参与派生的应用配置输入；本次真机已确认取自主 App Info.plist 的 `ak`，不能按 UUID 外形断言它每设备唯一。解码已有数据须保留同条签名的原始大小写与字节。
- `a5.b2` 是每次签名推进的序号；`a10` 的会话数值独立保存，不随每次请求递增。当前原生启动执行 `srand(time(NULL)); N=rand()%254+1`，构造 `3,N`；已有会话仍从原始样本续接。
- a5 的 signing profile 与缓存 a9 的 profile 分别选择；不能强制它们使用同一配置。
- `periodic` 模式从已有观察续接 60 秒采集缓存，联动 a5 与已知 a9 槽位。默认 `captured` 模式保留观察缓存；启用周期模式不等于重新采集硬件、传感器和环境数据。
- 检测时间校验采用已有 CRC 的差分，要求其他输入不变、时间字符串等宽；不支持任意修改全部设备字段后从零计算完整检测校验。
- a7/a8 的本地候选已经可复现。注册后的 XID/DFP 来自对应服务端成功响应，必须写回后续身份；客户端不能离线预测服务端将分配什么值。

缓存实现与历史对拍见 [续接修复记录](https://github.com/xiaozeng2296/keeta-device/blob/6197c52899b5bfcbed858004f064d7cd3c1eeea1/docs/archive/superseded/COLLECTION_REFRESH_20260929.md)。旧字段表中的“a10 每签递增”“a1 每设备唯一”“a9 只有一种固定算法”等说法不代表当前实现。

## 三种容易混淆的指纹

| 数据 | 当前处理方式 | 必要输入与限制 |
|---|---|---|
| mtgsig 内的 a9 | CRC32 + base64 + CBC + zlib；支持 AES、Twofish、修改 MDS 的 Twofish | 原始 a1、匹配的 default/legacy 或显式 SDK 参数；未知版本不保证支持 |
| 登录 I-series `fingerprint` | 已恢复格式的 AES-CBC 编解码 | 匹配的固定配置或调用方明确提供的 key/IV；不是全部同名字段的通用算法 |
| 注册 / bio 的 A envelope `fingerPrintData` | RSA 封装材料与 CBC payload 的组合 | 可用公钥构造；解码未知随机会话仍需要 payload key 或原始 RSA 明文材料及匹配设备/SDK 参数 |

a9 的 CRC 对压缩流计算，解码同时检查 padding、CRC 与完整 zlib。它不是“一把固定 AES key 通解全部数据”；历史失败包含配置不匹配以及密码分支判断错误。已实现的 `default`、`legacy` 是已验证配置标签，不是设备类别。

I-series 与 A envelope 的路由不能按字段英文名称互换。详细格式见 [a9 用法](archive/A9_USAGE.md)、[provider 边界](https://github.com/xiaozeng2296/keeta-device/blob/6197c52899b5bfcbed858004f064d7cd3c1eeea1/docs/archive/A9_PROVIDER_NOTES.md)、[SDK envelope](archive/ENVELOPE_SDK.md)、[corpse 变换](https://github.com/xiaozeng2296/keeta-device/blob/6197c52899b5bfcbed858004f064d7cd3c1eeea1/docs/archive/CORPSE_CODEC.md)。

## RPC

在项目根目录启动本地服务：

```sh
python3 keeta_rpc.py --host 127.0.0.1 --port 8799
```

服务配置 `KEETA_RPC_TOKEN` 时，请求须带对应的 `X-Token`。下列示例只引用环境变量，不包含认证值。`RPC_URL` 使用实际服务地址；本地默认如下：

```sh
RPC_URL=http://127.0.0.1:8799
curl --fail-with-body "$RPC_URL/decrypt" \
  -H "X-Token: ${KEETA_RPC_TOKEN}" -H 'Content-Type: application/json' \
  --data-binary @mtgsig.json
```

`mtgsig.json` 直接保存整条 mtgsig JSON，不需要外层包装。返回 `fields.a5`、`fields.a9` 等逐字段结果；应检查 `decryptable`，不能仅依据 HTTP 200 判断全部解码成功。

| 路由 | 用途与输入 |
|---|---|
| `GET /health` | 本进程能力与可用模式；不代表所有抓包都能解密 |
| `POST /decrypt` | 整条 mtgsig；a5 使用同条 a1/a3/a4，a9 使用同条 a1 |
| `POST /a9/decode` | `a9`、`a1`、可选 `profile` / `mode`；默认 profile 为 default |
| `POST /a9/encode` | `siua_json`、`a1`、明确的 `mode`，可选 `profile` |
| `POST /a5/decrypt`、`/a5/encrypt` | a5 专用编解码 |
| `POST /fingerprint/decrypt`、`/fingerprint/encrypt` | 已恢复的 I-series 等固定配置格式；别名 `/fp/*` |
| `POST /envelope/decode`、`/envelope/encode` | SDK envelope；输入 schema 见信封专题 |
| `POST /sign` | `identity` 或 `identity_path`、`method`、`url`、可选 `body`；会推进签名状态 |

`/decrypt` 未指定 a9 配置时，只尝试已验证的 default/legacy；显式 profile 或参数覆盖会关闭回退。`/a9/decode` 的 `mode=auto` 识别所选配置下的密码分支，不会自动切换 profile。加密须明确选择 `aes`、`twofish` 或 `twofish-mod`。

JSON 明文返回 `plain_json` 原结构和 `plain_explained` 可读说明，保留原数组索引；默认不重复返回 base64/text。解释标签属于已观察 schema 的展示辅助，不能替代原始数据。a2 为签名，不可“解密”；注册后的 a7/a8 是身份结果。

离线解 a9 也可使用 CLI：

```sh
python3 -m mtgsig.a9_cli decode -i mtgsig.json -o plaintext.json
python3 -m mtgsig.a9_cli decode -i old_mtgsig.json \
  --profile mtgsig/a9_legacy_profile.json -o old_plaintext.json
```

RPC 详细示例见 [接口说明](archive/A9_RPC.md)。更新、暂存验证与回滚见 [RPC 运维](../rpc/README.md)；本页整理没有启动服务或更新线上。

## 注册、登录与 Incognia

2026-10-03 更新：[从已有材料刷新 a7](research/A7_REFRESH_20261003.md) 已完成36账号服务端刷新、33账号营业店四接口验证，以及#44保存重载和多次真实到期续接。输入来自账号自身a5/a8、UUID、请求上下文及匹配SDK配置，经六字段+m320构造新envelope；a7必须取成功响应，不能离线计算。#71/#121/#126个人信息200而店铺403仍未解决。19:49已保留无worker模式替换空闲面板以加载当前代码；随后按同会话最新成功证据逐接口续接33账号可用状态，额度和失败账号保持，未启动原批次。维护器本身仍不会因上报成功自动清业务冷却。

注册执行器已经支持 OneID、newreg、scfg、区域状态及重复指纹上报等已观察阶段，并在下一次签名前应用成功响应。对应抓包顺序和当前实现见 [注册链](https://github.com/xiaozeng2296/keeta-device/blob/6197c52899b5bfcbed858004f064d7cd3c1eeea1/docs/archive/REGISTRATION_FLOW.md)、[a7/a8 阶段](https://github.com/xiaozeng2296/keeta-device/blob/6197c52899b5bfcbed858004f064d7cd3c1eeea1/docs/archive/root/REGISTRATION_ID_STAGES.md)。

邮箱协议已有 risk、apply、验证码提交及响应关联实现。历史完整抓包证明原生 App 会话发码/注册成功；现有协议尝试仍有 risk 拒绝，不能把抓包成功或本地密码往返当作新的协议登录成功。见 [登录协议](https://github.com/xiaozeng2296/keeta-device/blob/6197c52899b5bfcbed858004f064d7cd3c1eeea1/docs/archive/root/LOGIN_PROTOCOL.md)、[完整成功抓包审计](https://github.com/xiaozeng2296/keeta-device/blob/6197c52899b5bfcbed858004f064d7cd3c1eeea1/docs/archive/FULL_REGISTRATION_LOGIN_CAPTURE.md)。

Incognia token 的已观察封装与七个明文字段已有生成实现和离线对拍；它依赖 SDK 配置、安装标识、初始化/请求计数与时钟，不会自动注册一个新的安装身份。未知会话 token 也不能仅靠公钥解密。当前采集工作台使用的兼容策略见 [运行说明](OPERATIONS.md)，算法证据见 [Incognia 生成链](https://github.com/xiaozeng2296/keeta-device/blob/6197c52899b5bfcbed858004f064d7cd3c1eeea1/docs/archive/INCOGNIA_GENERATION_TRACE.md)。

## 验证口径

最新审计：从原生消息拷贝确认 Body 的 16,200 字节签名上限后，续包 a2 为 179/179；七份抓包的 566 条原生布局全部通过完整 a2、a5/a9 往返。另外 4 条 x0=4 仍标为 unsupported。边界、多字节字符及普通原生签名对拍证据见原生字段报告；原生包里的业务拒绝不能自动归因于离线算法错误。

本页是代码与已有证据的整理，没有执行新网络验证。算法往返、签名对拍、注册响应接受、邮箱发码与最终登录分别验收；任何一项通过都不能替代其他项目。所有历史报告保留在 `archive/`，其中“当前”“最新”等词仅指原报告的采样时间。
