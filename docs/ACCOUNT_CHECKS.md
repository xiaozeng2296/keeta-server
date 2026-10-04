# 账号与出口检查

账号状态现在只从 MySQL 当前活动 session 读取，不再查询或接管 SQLite 快照。每次调用沿用账号/安装锁、已用额度、最新签名序号、a7、接口冷却与出口。

```bash
# 离线验签：不发送业务请求，不保存试算计数
scripts/check_account_signatures.sh --all
# 检查指定账号实际配置的出口，未加 --execute 只预览
scripts/check_proxy.sh --accounts 1,2 --execute
# 先预览，需指定已有任务中的店铺
scripts/check_account_apis.sh --accounts 1,2 --shop-id SHOP_ID
# 显式发送，每账号最多四次业务请求，不循环重试
scripts/check_account_apis.sh --accounts 1,2 --shop-id SHOP_ID --execute
```

`--accounts` 支持逗号和范围，也可用 `--all`。店铺信息 → 主菜单 → 用本次菜单中的真实分类/SPU 请求 render → 营业时检查一个定制菜品。前置失败后的接口记录未验证，不能视为废号；闭店跳过定制。出口连通或签名通过不代表业务一定成功。

报告在 `exports/account-check-*/report.json`，只保存状态、接口与摘要，不包含 token、签名及代理密码。原始响应与失败诊断留在本机私有文件，MySQL 只记录引用与请求统计。检查不会自动删除账号。

普通 CLI 检查遵守冷却。面板手动恢复探测可越过对应冷却，但仍受硬额度与互斥锁约束；实际成功只清除已验证接口的冷却，保留其他冷却和用量。手动“解除冷却”标记为待验证，不启动采集。账号已暂停时明确手动探测可以验证，但不会自动解除暂停。

Worker 在账号池内轮换；普通接口无额外等待，仅同账号定制详情间隔。网络错误保留任务退避，不当成永久封号。连续四次 403 且涉及至少两个账号会终止本轮，重启不清该证据。到期冷却仅在启用自动恢复的执行任务中重新参与调度，额度不足仍等待；签名构造失败或缺材料明确显示原因。

出口通过面板“代理/节点”或 `farm.collection.prepare --routes` 明确配置。所有敏感配置加密保存；配置修改需要账号空闲。不再支持 `--local-batch`、`set_local_proxy.sh` 或第二套本地调度。

历史的 100 店实际压测结果见 [全流程](COLLECTION_FLOW.md)。新存储链的合成/数据库回归与历史实测分别记录，不能把改造前的压测当作改造后已经完成真实压测。
