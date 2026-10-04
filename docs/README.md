# 文档入口

日常运行和协议维护以本页列出的当前指南为入口。实验记录保留证据时点；归档不表示每一段都错误，但其中旧状态不能覆盖当前实现与回归结果。

| 目的 | 当前入口 |
|---|---|
| 启动、配置、采集与导出 | [OPERATIONS](OPERATIONS.md) |
| 账号检查、用量与冷却 | [ACCOUNT_CHECKS](ACCOUNT_CHECKS.md) |
| 理解账号到全部店铺任务的流程 | [COLLECTION_FLOW](COLLECTION_FLOW.md) |
| 理解签名接口与输入边界 | [PROTOCOL](PROTOCOL.md) |
| 查询a/b字段的已证结论和未知项 | [MTGSIG_FIELDS_STATUS](MTGSIG_FIELDS_STATUS.md) |
| 协议变化后如何定位、修改和验收 | [PROTOCOL_UPDATE](PROTOCOL_UPDATE.md) |
| 测试、干净发布包和采集验收 | [TESTING](TESTING.md) |
| 服务边界与优化顺序 | [ARCHITECTURE](ARCHITECTURE.md) |
| 本次精简迁移与待优化项 | [MIGRATION](MIGRATION.md) |
| 提交、推送与发布范围 | [VERSION_CONTROL](VERSION_CONTROL.md) |
| RPC部署 | [RPC说明](../rpc/README.md) |

学习协议时先读字段状态与协议总览，再按问题进入 [研究证据索引](research/README.md)。旧版本假设、旧容量实验和旧设计放在 [历史归档](archive/README.md)，不再作为部署教程。

文档维护规则：当前指南只写实际行为；一次性抓包对照写入research；已被替代的策略移入archive并标注替代依据。保留原证据，不把历史猜测改写成当时已经证明的事实。相同结论由一个当前入口维护，其余位置使用链接。
