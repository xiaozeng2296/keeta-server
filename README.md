# Keeta Server

现有账号的店铺采集、Web 管理、离线签名 RPC、代理路由及协议学习维护代码。以 2026-10-04 已验收的本地 100 店链路为迁移基线；不包含历史抓包、dump、账号、数据库口令、代理授权或采集结果。

## 安装

Python 3.9+，MySQL 8；本地采集任务使用 SQLite。建议新部署采用仍受支持的 Python 版本。Mihomo / GOST 3 按实际代理方式另行安装；常规离线采集无需 Frida 或手机常驻。

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
mkdir -p .private
chmod 700 .private
cp config/mysql.example.json .private/mysql.json
chmod 600 .private/mysql.json
# 编辑私有连接配置；接已有数据库时必须同时恢复原 account_encryption.key。
./scripts/python.sh -m farm.mysql_cli init
./scripts/start_panel.sh --no-worker --port 8788
```

面板绑定 `127.0.0.1`。`--no-worker` 只开管理端；MySQL 队列另开 `./scripts/start_worker.sh`。本地批次独立运行，业务结果只落本地，账号来源和控制仍依赖 MySQL。新环境需要导入自己的账号材料和配置出口。

## 入口

| 功能 | 入口 |
|---|---|
| Web 后台 | `scripts/start_panel.sh` |
| MySQL 队列 Worker | `scripts/start_worker.sh` |
| 本地批次准备 | `python -m farm.batch_prepare --help` |
| 本地采集与退出监督 | `scripts/start_batch.sh <prepared-folder>` |
| 推荐营业候选店铺 | `python -m farm.recommendations --help` |
| 交付验收与计时 | `python -m farm.batch_audit <folder>` / `farm.batch_report` |
| 签名 / 加解密 RPC | `scripts/start_rpc.sh --port 8799` |
| 独立代理核心 | `scripts/start_proxy.sh --help` |
| 链式代理 | `python -m tools.proxy_chain_bridge --help` |
| 日常账号验证 | `scripts/check_account_signatures.sh`、`scripts/check_account_apis.sh` |

先看 [运行指南](docs/OPERATIONS.md)，再看 [目录清单](PROJECT_MAP.md)、[全流程](docs/COLLECTION_FLOW.md) 和 [协议更新](docs/PROTOCOL_UPDATE.md)。[架构建议](docs/ARCHITECTURE.md) 区分已具备的进程边界和下一步待优化内容。

## 验证

```bash
./scripts/python.sh -m unittest discover -s tests -q
./scripts/python.sh scripts/smoke_services.py
./scripts/python.sh scripts/verify_repository.py
./scripts/python.sh scripts/check_staged.py --all
```

单测及服务烟测使用合成材料和本机临时端口，不调用真实业务接口；MySQL 集成测试需要专用测试库和显式开关。RPC 发布包会独立打包、测试、验证并支持代码回滚，见 [RPC 部署](rpc/README.md)。

## 数据与历史

`.private/` 保存数据库配置、密钥、账号账本和代理配置；`exports/` 保存交付。它们必须单独备份，不能提交。切换运行目录时要保留原额度、冷却、a7 和计数，不能只复制账号 JSON 后清零启动。迁移步骤见运行指南。

原研究与被替代文档留在旧仓库 `keeta-device` 的 `codex/keeta-project` 分支。这里仅保留当前指南、关键原生证据和必要算法笔记，不继承旧 Git 历史或独立暂存区发布机制。
