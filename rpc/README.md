# 离线签名与加解密 HTTP

启动：`scripts/start_rpc.sh --port 8799`，等价于 `python -m rpc`。服务默认监听 `127.0.0.1`；配置环境变量 `KEETA_RPC_TOKEN` 后以 `X-Token` 鉴权。

`server.py` 只处理 HTTP、鉴权、JSON 和错误状态，然后调用 `mtgsig.api.ROUTES` 对应函数。算法属于共享库；没有账号库、自动刷新、签名缓存、后台任务或远程部署代码。

| 接口 | 用途 |
|---|---|
| `GET /health` | 当前能力和 `stateless: true` |
| `POST /sign` | 提交 `identity` 对象、`method`、`url`、`body`，返回 `mtgsig` 和更新后的 `identity` |
| `POST /a2`、`/k2buf` | 请求签名和配套 mask 派生 |
| `POST /a5/encrypt`、`/a5/decrypt` | a5 JSON/密文转换 |
| `POST /a9/encode`、`/a9/decode` | a9 AES/Twofish/Twofish-mod 编解码 |
| `POST /fingerprint/encrypt`、`/fingerprint/decrypt` | 已知 I-series 等固定配置指纹；`/fp/*` 为同函数别名 |
| `POST /envelope/encode`、`/envelope/decode` | SDK 指纹信封构造/解码 |
| `POST /decrypt` | 整条 mtgsig 逐字段解析和含义说明 |

`/sign` 不接受 `identity_path`。调用者管理账号互斥与状态续接，下一次请求传回返回的 `identity`；服务不会在不同请求之间推进计数。Worker 直接调用同一库，仍由 MySQL 账号锁保护并持久化计数。a7 的到期网络维护由 Worker 完成，RPC 不发送上报或业务请求。

请求示例保存在调用者自己的 `request.json`：

```bash
curl --fail-with-body http://127.0.0.1:8799/sign \
  -H 'Content-Type: application/json' --data-binary @request.json
scripts/python.sh scripts/smoke_rpc.py --url http://127.0.0.1:8799
```

配置鉴权时同时传 `X-Token`；烟测从环境读取 token，只发送合成数据。参数及限制见 [协议指南](../docs/PROTOCOL.md)。

服务器更新只需拉取代码、安装依赖并重启进程，见 [运行指南](../docs/OPERATIONS.md)。不再存在 `remote_update.py`、SSH 上传发布包或维护两份文件白名单。
