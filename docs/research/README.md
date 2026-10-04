# 协议研究证据

本目录记录有具体输入、分支或对照支持的研究过程。当前运行规则以 [字段状态](../MTGSIG_FIELDS_STATUS.md) 和 [采集流程](../COLLECTION_FLOW.md) 为准；带日期的记录可能描述修复前状态。

| 主题 | 证据 | 阅读边界 |
|---|---|---|
| a7生成与到期维护 | [A7_REFRESH](A7_REFRESH_20261003.md) | 服务端返回值与已验证会话；不等于消除所有403 |
| b2、b17、b18 | [B_COUNTERS_RENDER](B_COUNTERS_RENDER_20261002.md)、[DYNAMIC_STATE_AUDIT](DYNAMIC_STATE_AUDIT_20261003.md) | 原生计数分支优先于旧数值关系启发式 |
| b16与render对照 | [B16_DEVICEINFO_COUNT](B16_DEVICEINFO_COUNT_20261002.md) | 请求适配与真实SDK上报是两种记录，不能互相冒充 |
| 会话字段生命周期 | [FIELD_LIFECYCLE_CONTROLS](FIELD_LIFECYCLE_CONTROLS_20261003.md) | 保留修复前后对照，当前维护器已主动刷新a7 |
| provider与原生字段来源 | [NATIVE_FIELDS](NATIVE_FIELDS_20261001.md) | a3、salt等成套配置；未验证版本仍须验证 |
| a2消息与收尾 | [A2_PASS2](../archive/A2_PASS2.md) | 以完整输出对拍，不能只匹配前缀 |
| a9算法与RPC | [A9_USAGE](../archive/A9_USAGE.md)、[A9_RPC](../archive/A9_RPC.md) | 保留原始a1、模式和配套配置 |
| fingerprint信封 | [ENVELOPE_SDK](../archive/ENVELOPE_SDK.md) | 密码还原不等于可以凭空构造完整设备画像 |

被替代的b17旧续接启发式放在 [旧缓存修复记录](https://github.com/xiaozeng2296/keeta-device/blob/6197c52899b5bfcbed858004f064d7cd3c1eeea1/docs/archive/superseded/COLLECTION_REFRESH_20260929.md)；费用和容量估算的早期设计放在 [旧队列设计](https://github.com/xiaozeng2296/keeta-device/blob/6197c52899b5bfcbed858004f064d7cd3c1eeea1/docs/archive/design/ACCOUNT_QUEUE_DESIGN.md)。这些文件用于追溯，不作为当前实现要求。
