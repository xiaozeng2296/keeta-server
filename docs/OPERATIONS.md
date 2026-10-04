# 部署与运行

命令在仓库根执行。`scripts/python.sh` 依次选择 `KEETA_PYTHON`、`.venv/bin/python`、`.private/python_path`、系统 Python；解释器路径文件只作为文本读取。

## 启动

安装 `requirements.lock`；将 `config/mysql.example.json` 复制到 `.private/mysql.json` 并配置 MySQL 8。接已有库时必须恢复原 `account_encryption.key`，均设为 0600。空库执行 `scripts/python.sh -m farm.mysql_cli init`。

```bash
scripts/start_panel.sh --no-worker --port 8788
scripts/start_worker.sh
scripts/start_rpc.sh --port 8799
```

Web 与签名 RPC 默认只监听本机。Worker 是唯一调度入口，只有面板明确排队的批次会执行；仅导入/准备不会自动采集。旧 Web 内嵌执行器选项仍兼容，但部署建议分进程。

## 代理

真实配置放 `.private/`，不要提交：

- `config/clash-pool.example.yaml` → `.private/clash-node-pool/config.yaml`。
- `config/clash-pool-setting.example.json` → `.private/clash-pool.json`，控制器 secret 与 YAML 一致。
- `config/routes.example.json` → `.private/routes.json`，每账号出口绑定与并发上限。
- 可选 `config/proxy-chain.example.json` → `.private/proxy-chain.json`。

```bash
scripts/start_proxy.sh                  # 仅检查配置
scripts/start_proxy.sh --register       # 保存面板节点映射
scripts/start_proxy.sh --run            # 独立核心，不改桌面 Clash
scripts/python.sh -m tools.proxy_chain_bridge --config .private/proxy-chain.json --run --gost /opt/homebrew/bin/gost
```

`Clash → IPFoxy` 是串行出口，不能当作两个 IP。节点名称不同也不保证公网 IP 不同。现有默认绑定每条路由最多一个请求；批次 routes 中可显式设定上限，迁移账号保留原上限。

## 准备、启动、验收

账号从面板导入，邮箱缓存随运行状态保留。a7 维护需要匹配的材料，见 `tools/refresh_fingerprint.py --help`。

```bash
# 推荐发现必须显式执行，使用所选账号当前会话/出口/额度
scripts/python.sh -m farm.recommendations --account 1 --latitude=-23.55 --longitude=-46.63 \
  --city-id 102302389 --pages 6 --output exports/recommendation-run --execute

# shops.json 格式见 config/shops.example.json；使用文件中的全部店铺
scripts/python.sh -m farm.batch_prepare --shops .private/shops.json --accounts 1,2,3 \
  --routes .private/routes.json --concurrency 3 --detail-delay 4 --execute
```

准备器仅创建 ready 批次并保存明确的出口配置，不暂停账号、不重置额度、不发送业务请求。到面板选择输出的 run_id 和账号，设置并发、间隔并启动。Worker 保留冷却、额度与真实签名状态。加 `--verify-open` 会先核验所有 shopInfo；全部营业才释放菜单，发现闭店则停止在明确阻塞状态，不自行替换范围。

```bash
scripts/python.sh -m farm.batch_report RUN_ID --output exports/benchmark.json
scripts/python.sh -m farm.batch_audit exports/execution-EXECUTION_ID
```

普通接口无额外四秒等待，仅同账号定制详情需要间隔。403 保护、手动停止及额度等待不会靠重启清零。网络问题与 403 分开处理；失去数据库连接后先提交已落盘响应，再恢复调度，不重复发包。

默认交付：`exports/execution-ID/delivery.xlsx` 和仅含该表的 `delivery.zip`。超长字段在表内“长字段内容”工作表；按引用ID和分片序号拼接即可恢复原值。`delivery.coverage.json` 是本机验收报告，不放进默认 ZIP。响应体在 `.private/responses/`。

## 从旧双账本迁移

旧 SQLite 只在一次性私有迁移中只读使用，不再是新程序依赖。必须先停止旧调度、确认无在途请求，再备份原数据库/密钥和旧目录；按活动 session 合并最新签名/a7、逐次 attempts、预算下限、冷却和休息。不能把继承的预算快照逐批累加。

迁移幂等标记与备份保留在本机；旧历史面板改读 `history.json`。旧目录保存原 SQLite 和原 ZIP，新运行目录不读取它们。历史 DB 响应可迁成本机引用；启用后旧代码不能再直接解压该字段。代码回滚不能回滚已发生的请求、额度与签名计数。

备份/搬机必须同时保存 MySQL、`.private` 和需要的 `exports`。不要只迁账号 JSON 后重新从零计数。

## 验证

```bash
scripts/python.sh -m unittest discover -s tests -q
scripts/python.sh scripts/smoke_services.py
scripts/python.sh scripts/verify_repository.py
scripts/python.sh scripts/check_staged.py --all
```

MySQL 集成测试额外要求 `KEETA_MYSQL_TESTS=1`、`KEETA_MYSQL_TEST_CONFIG=/绝对路径/mysql.json`。配置必须使用 `keeta_test_` 加十六进制随机后缀的独立数据库，且 `test_database: true`；不得指向实际账号库。使用合成账号与模拟业务 HTTP，验证额度、崩溃恢复、响应文件、闭店/不可售和营业核验。
