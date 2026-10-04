# 当前离线协议

本项目支持已有账号的店铺采集，以及同一套签名/加解密函数的 RPC 调用。不包含新账号注册、邮箱验证码登录、真机注入或旧样本近似重签执行器。历史研究可从 [整理前版本](MIGRATION.md) 追溯。

## 实现对应

| 模块 | 当前用途 |
|---|---|
| `mtgsig/signer.py` | `FullSigner`、完整 a2、a5 解码、从已有 mtgsig 提取身份 |
| `mtgsig/a2.py` + 四个 `.bin` | canonical 请求、a2 混合与查表；算法表为必需资源 |
| `mtgsig/mtg_crypto.py`、`a9_codec.py` | a5 RC4 变体、指纹 AES、Twofish 分组原语及 a9 编解码 |
| `mtgsig/provider_config.py` | 成套 a3/salt 配置及 mask 派生 |
| `mtgsig/collection_cache.py` | 基于已观察快照的周期缓存和已知 CRC 差分 |
| `mtgsig/fingerprint_refresh.py`、`registration_checksum.py`、`registration_state.py` | a7 report 构造、m320 校验、真实上报事件及成功响应回填 |
| `mtgsig/envelope_codec.py` | fingerprint 报文信封；构造用公钥，解码还需对应会话材料 |
| `mtgsig/request.py`、`request_trace.py`、`incognia_state.py`、`incognia_token.py` | 最终请求时间/trace、显式启用的 Incognia 状态与编码 |
| `mtgsig/api.py` | JSON 调用适配及解码字段说明；不管理账号或发送请求 |

`mtgsig/keeta_const.json`、`a9_legacy_profile.json`、`embedded_rsa_pubkeys.json` 和四个算法表必须随代码保留。它们是配置/算法资源，不是账号材料。`legacy` 是仍可能用于已有身份的密码配置，不能与退役的历史签名脚本混为一谈。

## 签名与状态

输入包括本账号身份/采集快照、配套 provider、method、URL、实际 body，以及会话计数。输出完整 mtgsig 和续接状态。

- a2 绑定 canonical URL、Body UTF-8 前 16,200 字节、完整 payload 与计数；实际 HTTP Body 不截断。JSON 序列化、URL 编码与实际发送字节必须一致。
- a1 是原生应用配置输入，保留同条签名字节；a3 必须与 salt 配套，不能只改数字。
- a4 每请求取当前秒；b2 为签名序号；b17/b18 按已证分支推进。a10 第二段为同 SDK 启动的随机值，不能当请求次数。
- b16 记录三类上报次数与相对时点；当前 render 保留已验证的兼容补齐，info/report 使用真实 begin/finish 事件续接。其他未知生命周期不凭空推导。
- a7 来自 `/fingerprint/v1/info/report` 成功响应 `data.result`，Worker 按服务端 interval 在业务前维护；刷新成功不等于业务接口解除冷却。
- periodic 缓存从已有观察续接 a5/a9；不重新测量硬件、传感器或恢复全部原生采集过程。
- a9 的密码配置可与当前 a5 不同。仅支持已验证的配置与模式，未知布局应明确报错。

逐字段来源和未完成边界见 [字段状态](MTGSIG_FIELDS_STATUS.md)，更新步骤见 [协议维护](PROTOCOL_UPDATE.md)。

## Python 与 RPC

```python
from mtgsig.signer import FullSigner

signer = FullSigner(identity)  # identity 是本账号的字典；函数复制输入
signature = signer.sign(method, url, body)
next_identity = signer.persist_counter()
```

请求状态和持久化由调用者负责；Worker 会在出网前保存已预留状态，发送失败也不倒退计数。RPC `/sign` 采用相同调用，返回 `mtgsig`、`identity`，不支持服务器文件路径。

整条解码可直接调用 `mtgsig.api.op_decrypt(mtgsig)` 或 `POST /decrypt`。返回原结构 `plain_json` 与可读说明；必须检查每个字段的 `decryptable`。a2 不可逆，a7/a8 是服务端身份值，不能作为通用密文解开。

常用编码参数：a9 使用 `siua_json`、原始 `a1`、明确 `mode`；a5 使用 `plain_json`、同条 a1/a3/a4 及匹配 signing profile；SDK envelope 使用 a1、明文及会话 key/material，无法仅靠公钥解密任意捕获信封。完整接口见 [RPC](../rpc/README.md)。

## 当前验证与历史证据

常规回归保留完整 a2 边界、原生 a9 block/CBC 向量、m320 向量、a5/a9 往返、provider 错配拒绝、周期缓存、a7 状态以及 RPC 真正 HTTP 调用。私有抓包不会被隐式读取。

历史原生对拍、字段偏移与局限见 [证据索引](research/README.md)；这些历史记录不表示整理后又发送了相同规模的真实业务请求。
