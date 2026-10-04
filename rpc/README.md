# 离线签名 RPC

`../keeta_rpc.py` 提供共享算法的 HTTP 入口，默认 `127.0.0.1:8799`。采集器直接调用 `farm/fullsign.py`，不需要额外经过 RPC 网络跳转。RPC 的 `/sign` 有缓存和签名计数；不要与 Worker 同时写同一份账号身份档。

```bash
scripts/start_rpc.sh --host 127.0.0.1 --port 8799
scripts/python.sh rpc/smoke.py --help
```

需要鉴权时由进程环境传入 `KEETA_RPC_TOKEN`，调用方用 `X-Token`；不写入代码或版本库。接口与密码分支见 [PROTOCOL](../docs/PROTOCOL.md)。注册/登录密码接口保留兼容，采集主流程不调用它们；它们不代表无需额外材料即可创建新账号。

## 更新已有远端服务

先把 `config/rpc-deploy.example.json` 复制为 `.private/rpc-deploy.json`，填写 SSH Host、安装目录、服务名与远端 venv 路径。SSH 认证在机器上自行配置；脚本不携带账号材料或认证私钥。

```bash
# 上传到隔离暂存目录并验证，不切换服务
python rpc/deploy.py --stage-only
# 显式正式更新：备份代码、安装、重启服务、健康/密码烟测；失败回滚代码
python rpc/deploy.py
# 显式回滚一次发布
python rpc/deploy.py --rollback RELEASE_ID
```

运行文件与 RPC 测试清单唯一来源是 `rpc/remote_update.py`。打包只含该清单，不含本地业务库/代理授权。首次部署先按根 README 安装 Python 依赖，再安装 `deploy/keeta-rpc.service` 示例，填真实工作目录与私有环境文件。远端配置、身份状态和密钥不由代码发布包覆盖。

发布中断仍须人工核对备份和服务状态；不能回滚已发送请求、a7或签名计数。SIGKILL/断电不能承诺自动完成代码回滚。
