# Keeta Server

已有账号的店铺采集与管理。只有一条任务执行链：Web → MySQL 队列 → Worker；业务响应保存在本机，数据库只保存账号加密材料、用量、冷却、任务与响应引用。离线签名共用 `mtgsig`，RPC 只把这些函数暴露为 HTTP 接口。

## 安装与启动

Python 3.9+、MySQL 8；新部署建议采用仍受支持的 Python 版本。Clash/Mihomo、GOST 按出口需求另装。正常采集不需要手机、Frida 或研究工具。

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
mkdir -p .private
chmod 700 .private
cp config/mysql.example.json .private/mysql.json
# 填写本机配置；使用已有数据库时恢复原 account_encryption.key。
./scripts/python.sh -m farm.cli init
./scripts/start_panel.sh --port 8788
# 另一个终端启动唯一的队列执行器：
./scripts/start_worker.sh
```

离线计算接口按需启动：`./scripts/start_rpc.sh --port 8799`。Worker 直接调用签名库，采集不经过 RPC。账号和出口在面板导入、配置；仅准备批次不会自动发请求。

## 目录

- `farm/`：按账号、采集、存储、交付、网络、Web 分组，见 [目录说明](PROJECT_MAP.md)。
- `mtgsig/`：当前签名、指纹加解密、a7 上报构造与必要算法资源。
- `rpc/`：无账号状态的 HTTP 包装，无部署器、远程更新器或身份文件读取接口。
- `tests/`：现用功能回归，按模块分组，见 [测试用途](docs/TESTING.md)。
- `scripts/`、`config/`、`deploy/`：启动、日常检查、示例配置和 Linux 服务单元。
- `docs/`：当前用法与必要协议证据；旧实验从 Git 历史找回。

## 更新服务器

```bash
git pull --ff-only
./scripts/python.sh -m pip install -r requirements.lock
sudo systemctl restart keeta-rpc
```

若更新采集服务，确认当前没有在途任务后重启 `keeta-web`、`keeta-worker`；代理代码变化时再重启 `keeta-proxy`。本机进程用相同入口重新运行即可，无单独发布包。具体步骤见 [运行指南](docs/OPERATIONS.md)。

## 验证与数据

```bash
./scripts/python.sh -m unittest discover -s tests -t . -q
./scripts/python.sh scripts/smoke_services.py
./scripts/python.sh scripts/verify_repository.py
```

默认测试使用合成数据；真实 SQL 验证需显式提供独立测试库。真实账号请求使用 [账号检查命令](docs/ACCOUNT_CHECKS.md)，不会因运行单测而发起。

`.private/` 与 `exports/` 不提交。默认交付 ZIP 只有 `delivery.xlsx`，超长子菜嵌入工作簿“长字段内容”页。备份需要同时保存 MySQL、私有密钥、响应文件和需要的交付。更新代码不重置额度、冷却、签名计数或 a7。
