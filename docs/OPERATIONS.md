# 部署与运行

所有命令在新仓库根执行。`scripts/python.sh` 依次选择 `KEETA_PYTHON`、`.venv/bin/python`、本机 `.private/python_path`、系统 `python3`。解释器路径文件只作为文本读取。

## 控制数据库与后台

1. 安装根目录 `requirements.lock`（依赖范围见 `requirements.txt`）；复制 `config/mysql.example.json` 到 `.private/mysql.json` 并填写。
2. 空库使用 `python -m farm.mysql_cli init` 初始化；已有库必须带上原 `account_encryption.key`。这两个文件都放在 `.private/`，权限 0600。
3. `scripts/start_panel.sh --no-worker --port 8788` 启动 Web 管理端。
4. MySQL 任务使用 `scripts/start_worker.sh`；本地任务使用下文的批次入口，两种运行方式不能同时花费同一账号。

Web 只有本地 Host/Origin/CSRF 检查，尚无多用户登录系统，默认只绑定回环。远程访问走可信隧道。MySQL Worker 沿用唯一执行器租约，退出停止领取并保留未完成任务。不要配置无限自动重启本地批次以绕过 STOP / 403 保护。

默认不带 `--no-worker` 的旧面板入口仍会内嵌执行器，保留兼容；需要进程隔离时使用上面的两个命令。

## 代理

配置模板只含占位符，真实凭据放私有文件：

- `config/routes.example.json` → `.private/routes.json`：本地批次的出口、每出口并发和账号绑定。每个账号必须有明确绑定。
- `config/clash-pool.example.yaml` → `.private/clash-node-pool/config.yaml`：独立 Mihomo 核心监听端口，填入可用节点。
- `config/clash-pool-setting.example.json` → `.private/clash-pool.json`：核心路径、控制器和节点端口；secret 必须与 YAML 一致。
- `config/proxy-chain.example.json` → `.private/proxy-chain.json`：可选 GOST 3 链式代理。

```bash
# 只检查文件配置，不发业务网络请求
scripts/start_proxy.sh
# 显式注册面板节点映射（写控制数据库）
scripts/start_proxy.sh --register
# 前台运行独立核心，SIGTERM 向子进程转发
scripts/start_proxy.sh --run
# 可选链式出口，私有配置必须为 0600
python -m tools.proxy_chain_bridge --config .private/proxy-chain.json --run --gost /usr/local/bin/gost
```

独立核心与用户桌面 Clash 的全局选择互不修改。节点不同不保证公网 IP 不同，实际出口需用代理检查验证。`Clash → IPFoxy` 是一条串行出口链，不应按两个独立 IP 统计并发。`routes.json` 中端口必须与启动的监听端口一致；未配置时不会凭空创建可用节点。

## 本地采集：准备、运行、验收

账号从面板或 `farm.mysql_cli import-accounts` 导入。a7 维护材料须先通过 `tools/refresh_fingerprint.py` 的预检/显式配置流程；已有会话沿用当前状态。完整参数见各入口 `--help`。

店铺输入使用 `config/shops.example.json` 格式：`shop_id,latitude,longitude,city_id`，可带 `shop_name`。也可从推荐发现得到 `candidate-pool.json`：

```bash
# 不加 --execute 仅预览；页数有明确上限，沿用账号当前出口与额度
python -m farm.recommendations --account 1 --latitude=-23.55 --longitude=-46.63 \
  --city-id 102302389 --pages 6 --output exports/recommendation-run --execute

# 必须把候选文件选成希望采集的范围，准备器会使用输入的全部店铺
python -m farm.batch_prepare --shops .private/shops.json --accounts 1,2,3 \
  --routes .private/routes.json --concurrency 3 --detail-delay 4
# 上一步是预览；确认配置后加 --execute 创建批次（不启动采集）
python -m farm.batch_prepare --shops .private/shops.json --accounts 1,2,3 \
  --routes .private/routes.json --concurrency 3 --detail-delay 4 --execute

scripts/start_batch.sh .private/local100-YYYYMMDDTHHMMSSZ
python -m farm.batch_report .private/local100-YYYYMMDDTHHMMSSZ
python -m farm.batch_audit .private/local100-YYYYMMDDTHHMMSSZ
```

目录名由实际店数和 UTC 时间生成，以准备器输出为准。准备器核对活动会话及锁，继承最新本地签名/a7/额度/冷却，再暂停这些账号的数据库调度。这个控制动作会写 MySQL；采集运行过程的业务响应只写本地 SQLite。准备后不自动解除账号的数据库暂停，避免两套状态同时推进。

若加 `--verify-open`，先逐店核验 shopInfo；全部状态为营业才释放菜单。发现闭店则保留核验结果并阻塞，不偷偷替换店铺；需明确调整店铺范围。推荐卡营业状态只是候选，不保证核验时仍在营业。未启用该选项时按通常闭店跳过详情策略采集。

运行保留每账号额度、接口冷却、出口退避、定制详情间隔和连续 403 保护。普通接口不加四秒间隔。售罄/未到销售日仅在有菜单记录及明确证据时跳过详情。监督进程记录真实退出码，不自动重启；`--resume` 是显式恢复操作，不能作为定时重试命令。

交付是 `delivery.xlsx`、`delivery.coverage.json`、`delivery.zip`，验收额外生成 `delivery.audit.json`。完整店数、实际发送、有效成功、403、网络错误和跳过单独统计，不能用 HTTP200 总数替代完成率。

## 运行状态迁移

本次源码整理未切换原来已经运行的 Web / 代理服务。迁移运行环境时：

1. 确认没有采集或探测在途，按正常流程停止原控制/采集入口；保留旧目录作回退。
2. 备份原 MySQL 及对应密钥。把 `.private/mysql.json`、`account_encryption.key`、所有仍需累计额度的 `local*-*` 账本（含 `.key`、加密路由、manifest、锁/停止记录）和 `account-checks/` 一起迁移，不能只取最新一份账号。
3. 迁移所需 `exports/` 和独立代理配置。原运行 manifest 中 `private/output`、handoff 来源、latest 指针含绝对路径，统一改为新数据目录；不要更改账号、attempts、预算、冷却或签名字段。
4. 同机过渡可将新项目 `.private` 和 `exports` 同时链接到旧数据目录，原路径与账本保持一致。只能有一个控制/采集环境拥有这些账号；不要让两边自动任务同时操作。
5. 先只启动新 Web `--no-worker` 验证历史账本与每日汇总，再启代理和明确批次。代码回滚可以恢复旧代码，不能回滚已发送请求及账户计数。

源代码不依赖旧目录；运行状态迁移属于运维切换，不能通过单测推断已经部署生效。
