# 测试与发布

```bash
scripts/python.sh -m unittest discover -s tests -q
scripts/python.sh scripts/smoke_services.py
scripts/python.sh scripts/verify_repository.py
scripts/python.sh scripts/check_staged.py --all
```

- 签名：完整 a2、a5/a9 编解码、provider 配套、缓存生命周期、b 系列计数和真实 prepared request 字节。
- a7：到期、响应持久化、失败退避、同账号串行与未完成事件，不用刷新成功冒充业务解除冷却。
- 统一队列：菜单扩展、render、定制、闭店/不可售、额度、403、响应恢复与导出。`test_mysql_integration` 使用合成账号和真实隔离 SQL，`test_local_response_files` 验证响应不入 SQL、缺文件/坏哈希报错及长字段在表内无损保存。
- Web / MySQL：面板和调度的单元测试；`test_mysql_integration` 需要独立测试库及 `KEETA_MYSQL_TESTS=1`、`KEETA_MYSQL_TEST_CONFIG`。配置需 `test_database: true`、数据库名 `keeta_test_` 加随机十六进制后缀。禁止拿生产库运行集成测试。缺少私有原生样本的历史向量测试会明确 skip。
- 代理：路由、脱敏、配置与桥接生命周期；服务烟测使用临时本地代理子进程，不验证实际公网节点质量。
- RPC：独立临时端口 HTTP 烟测、完整发布包导入、暂存测试和失败回滚。远端 SSH 部署只在显式调用发布脚本时进行。

发版以 Git 索引中的文件为准，复制到干净临时目录，在独立 venv 安装 `requirements.txt` 并执行上述检查；不要借用旧项目 `.private` 或研究源码。推送前检查精确暂存字节，提交后核对远端 HEAD。新仓库使用普通 Git 提交，不再维护隐藏的另一套发布分支/暂存区。

真实批次需另外验收店铺范围、菜单/render覆盖、营业且可售商品定制/嵌套完整度、跳过证据、Excel行数/公式转义、表内长字段重组哈希、ZIP与在途账本。离线测试不能保证账号永不403，也不能替代长时间实跑。
