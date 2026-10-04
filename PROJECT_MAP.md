# 当前目录与入口

```text
farm/
  accounts/     导入、选号、验证、邮箱缓存、冷却操作、a7 维护
  collection/   批次准备、推荐发现、任务扩展、执行调度、请求上下文
  storage/      MySQL/建表、账号加密、删除操作、本机响应与原子文件
  delivery/     纯字段映射、Excel/ZIP 导出、完整度验收、请求统计
  network/      代理适配、Clash 核心进程、GOST 链式代理
  web/          HTTP 管理端、页面和静态资源
  executor.py   唯一 Worker 进程入口
  cli.py        初始化、导入、账号及任务管理 CLI
  paths.py      数据目录定位，不修改 sys.path
mtgsig/         共享离线签名与加解密库，独立于 farm、MySQL 和 RPC
rpc/            HTTP 包装；python -m rpc
scripts/        启动、日常检查、测试与提交检查
config/         无真实凭据的配置示例
deploy/         Linux systemd 服务示例
tests/          按 accounts/collection/storage/network/web/protocol/http_api 分组
docs/           当前指南、协议说明和关键原生证据
```

| 操作 | 入口 |
|---|---|
| Web | `scripts/start_panel.sh --port 8788` |
| Worker | `scripts/start_worker.sh` |
| 离线签名/加解密 HTTP | `scripts/start_rpc.sh --port 8799` |
| Clash 核心 | `scripts/start_proxy.sh --run` |
| GOST 桥接 | `python -m farm.network.chain --help` |
| 批次准备 | `python -m farm.collection.prepare --help` |
| 推荐发现 | `python -m farm.collection.recommendations --help` |
| 交付验收/统计 | `python -m farm.delivery.audit` / `farm.delivery.report` |
| 日常账号检查 | `scripts/check_account_signatures.sh` / `check_account_apis.sh` |
| a7 维护 | `python -m farm.accounts.maintenance --help` |
| 管理 CLI | `python -m farm.cli --help` |

`mtgsig/signer.py` 是完整签名入口；`mtgsig/api.py` 只负责 JSON 参数与返回格式，供 RPC 或 Python 调用。核心算法无需启动 Web、连接数据库或持有服务器身份文件。

旧文件路径不保留转发壳。自定义外部脚本需要改为以上模块路径；账号数据与数据库表结构不因此改变。清理范围及旧版本定位见 [整理记录](docs/MIGRATION.md)。
