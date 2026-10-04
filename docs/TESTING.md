# 保留哪些测试，为什么保留

测试按当前功能分组。运行服务不会加载测试；常规测试不读真实账号、不探测平台，不要求历史镜像或抓包。

```bash
scripts/python.sh -m unittest discover -s tests -t . -q
scripts/python.sh scripts/smoke_services.py
scripts/python.sh scripts/verify_repository.py
```

| 分组 | 验证内容 | 对应风险 |
|---|---|---|
| `tests/protocol/` | a2 完整值及 16,200 字节边界、a5/a9、原生 Twofish/CBC 向量、信封、provider、缓存、m320、上报回填、请求新鲜度 | 重构后签名变字节、错用配置、计数/缓存生命周期倒退 |
| `tests/accounts/` | 身份匹配、导入后的四接口模板、探测/邮箱缓存、a7 到期/退避/维护额度 | 混用账号材料、错误解除冷却、上报失败后继续业务 |
| `tests/collection/` | 请求上下文、render 扩展、定制/闭店/不可售、响应判定及字段映射 | HTTP200 被误当成功、漏菜、错误跳过 |
| `tests/storage/` | 加密、锁/租约、事务额度、恢复与不重复发包、本机响应、长字段和交付包 | 额度漏记、重发、响应丢失、数据库收到响应体 |
| `tests/network/` | 代理格式、认证与链式出口、GOST 配置和进程退出 | 走错出口、泄露代理凭据、遗留进程 |
| `tests/web/` | 面板导入、任务/账号状态、缓存合并、删除冲突 | 页面统计误导或误删运行中的资料 |
| `tests/http_api/` | JSON 编解码适配、真实 HTTP、鉴权、无状态计数续接、拒绝 identity_path | HTTP 与库行为不一致、服务读写账号文件 |

固定 fixtures 只保留被上述测试实际引用的脱敏向量。它们用于独立预期值，不能用同一函数生成预期后宣称原生一致。

已经删除：旧单账号爬虫、注册登录/邮箱、bootstrap/OneID/NTP/SCFG/collector、真机观察/仿真工具、RPC 自定义发布/回滚、流量费用，以及依赖未随仓库提供私有样本的测试。对应代码一并移出，原始版本见 [整理记录](MIGRATION.md)。

## 独立数据库验证

默认跳过显式数据库集成项。启用需设置 `KEETA_MYSQL_TESTS=1` 与 `KEETA_MYSQL_TEST_CONFIG=/绝对路径/mysql-test.json`。配置要求 `test_database: true`、数据库名 `keeta_test_` 加随机十六进制后缀。测试只用合成账号/模拟业务响应，不能指向实际账号库。

```bash
KEETA_MYSQL_TESTS=1 KEETA_MYSQL_TEST_CONFIG=/path/to/mysql-test.json \
  scripts/python.sh -m unittest discover -s tests -t . -q
```

## 服务与真实账号检查

`scripts/smoke_services.py` 用临时端口启动 RPC，执行真实 HTTP 密码操作；用模拟 Store 验证 Web；用临时核心进程验证代理生命周期。不会启动新业务批次。

`scripts/smoke_rpc.py --url http://127.0.0.1:8799` 检查正在运行的 RPC。`scripts/check_account_signatures.sh`、`check_account_apis.sh` 和 `check_proxy.sh` 是日常诊断入口；网络操作需显式 `--execute`，用途见 [账号检查](ACCOUNT_CHECKS.md)。

测试通过只证明这些边界。真实业务仍需验收菜单/定制覆盖、闭店不可售证据、额度和请求结果，不能承诺账号永不 403。
