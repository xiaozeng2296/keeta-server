# 协议更新流程

先读 [当前字段状态](MTGSIG_FIELDS_STATUS.md)，再按下面的顺序更新。原2026-10-01核对记录保存在 [历史更新记录](https://github.com/xiaozeng2296/keeta-device/blob/6197c52899b5bfcbed858004f064d7cd3c1eeea1/docs/archive/design/PROTOCOL_UPDATE_20261001.md)，provider与原生分支证据见 [NATIVE_FIELDS](research/NATIVE_FIELDS_20261001.md)。

1. **固定基线**：记录App/build、SDK、provider/profile、请求接口、出口及源码版本。保存原始材料与脱敏摘要，保留同会话请求顺序。不要先改变多个值或把新的设备字段与旧身份混合。
2. **确定差异层**：先比较实际发送的method、canonical URL、UTF-8 body与headers，再比较a5/a9明文及会话状态。区分HTTP拒绝、业务码失败、结构/目标不匹配和网络错误。
3. **追溯字段来源**：标记固定配置、请求级、会话级、缓存级或服务端返回值。a3与salt成套验证；a10不是请求次数；b2/b17/b18按各自分支推进；a7取对应成功上报响应，不能由其他账号拼接。
4. **最小修改**：只修改已定位层，并添加能区分旧错行为的回归。密码层改动需完整输出对拍，不只验证前缀；请求重建需与实际prepared request字节一致。原始证据保留，派生结果另存。
5. **状态验证**：检查保存重载、重试、异常退出、并发领取、时钟及跨日用量。未知发送结果仍保留额度，成功刷新a7不自动清除业务冷却。
6. **逐层验收**：离线向量 → 单元测试 → 干净发布副本 → 明确范围的真实请求 → 批次完整度。算法往返成功不等于服务端接受，单接口200也不等于全部业务可用。
7. **更新单一当前结论**：最终行为写入字段状态页或采集流程；实验细节进入research；推翻的启发式移入archive并注明替代证据。同步RPC解释标签、部署清单、测试和版本说明。

## 工具入口

- `tools/protocol_watch.py`、`tools/protocol_probe.js`、`tools/protocol_lifecycle.js`、`tools/protocol_trace.js`：显式启动的原生观测，按各自参数控制范围。
- `python -m farm.account_checks signatures --help`：离线请求/签名检查。
- `tools/refresh_fingerprint.py --help`：a7维护预检与显式上报；默认行为以命令帮助为准，不把读取材料当成已发送。
- [测试说明](TESTING.md)：各层对应的回归和发布验收。

逆向分支补迁的算法笔记、8个离线工具和参数示例见 [离线研究指南](research/OFFLINE_RESEARCH.md)。研究依赖独立，普通Web/RPC运行不需要安装。

## 仍须保留的边界

已有a2/a5/a9算法及部分状态续接不等于完整设备采集器已恢复。未知SDK配置、新body布局、其他上报生命周期及服务端风控原因需要各自证据。此前100店成功交付不能替代新版本或新账号材料的验证。
