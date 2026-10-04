# 保留的算法笔记

这里保留仍有学习价值的算法细节、字段来源及注册/登录状态证据；文中的“当前/最新”指当时采样日期。字段最终语义以 [当前字段状态](../MTGSIG_FIELDS_STATUS.md) 为准。

- [a2 pass2](A2_PASS2.md)：完整16字节变换与历史布局分析；后续body长度边界见当前原生研究。
- [a9使用](A9_USAGE.md)、[a9 RPC](A9_RPC.md)：编解码格式与已知profile。
- [SDK信封](ENVELOPE_SDK.md)：RSA/AES封装、会话材料和能力边界。
- [设备字段历史底稿](root/DEVICE_FINGERPRINT_FIELDS.md)、[指纹历史底稿](root/FINGERPRINT.md)：逆向定位过程；不能把早期猜测覆盖后续b16/b17/b18结论。

重复部署教程、旧费用模型、被替代的b17启发式、大量一次性实验放在[旧项目的固定归档版本](https://github.com/xiaozeng2296/keeta-device/tree/6197c52899b5bfcbed858004f064d7cd3c1eeea1/docs/archive)。新项目不重复复制整套历史。

本轮从研究分支补齐的 27 份资料，按主题整理在 [离线研究指南](../research/OFFLINE_RESEARCH.md)。原始 blob/SHA-256 见 [来源清单](../research/PROTOCOL_MIGRATION_MANIFEST.json)。
