# 协议逆向资料与离线复核

运行与维护先读 [协议总览](../PROTOCOL.md) 和 [字段状态](../MTGSIG_FIELDS_STATUS.md)。本页连接算法来源、原生证据和复核工具，不改变采集任务、账号状态或现有服务。

## 来源和阅读顺序

旧仓库远端目前没有单独名为 `reverse` 或 `protocol` 的分支。完整研究资料主要在 `codex/keeta-project@6197c52899b5bfcbed858004f064d7cd3c1eeea1`；旧 `main@5b6b0c3` 和 `keeta-farm@2f16743` 有早期底稿，`codex/keeta-console@5729b082` 是运行发布分支。已对照这些本地分支及远端分支引用；本轮从已脱敏的 project 固定提交补迁，未切换或改写旧仓库。

在初版已保留的运行代码、字段研究和算法笔记之外，补入 27 份研究文档与 8 个离线工具。逐文件来源、原始 Git blob 和 SHA-256 见 [迁移清单](PROTOCOL_MIGRATION_MANIFEST.json)。不需要旧仓库即可阅读这些文档和运行合成测试；原生指令复核仍须自行提供匹配镜像。

| 学习问题 | 本地资料 | 对应实现或验证 |
|---|---|---|
| 完整 a2、a5 与 b13 的证据 | [a2收尾](../archive/A2_PASS2.md)、[b13历史](../archive/A5_B13_AUDIT.md)、[大body边界与provider原生证据](NATIVE_FIELDS_20261001.md) | `farm/fullsign.py`、`verify_a2_pass2.py` |
| a9 profile、派生参数和旧样本为何不同 | [provider](../archive/A9_PROVIDER_NOTES.md)、[历史样本来源](../archive/A9_OLD_SAMPLE_FINDINGS.md)、[a9用法](../archive/A9_USAGE.md) | `mtgsig/a9_codec.py`、`provider_config.py`；3个a9工具 |
| 字段总表与m系列 | [V5字段底稿](../archive/root/V5_SIGN_FIELDS.md)、[corpse](../archive/CORPSE_CODEC.md)、[m175](../archive/M175_SOURCE.md)、[m239](../archive/M239_SOURCE.md)、[m324](../archive/M324_SOURCE.md) | `mtgsig/`中同名模块；现有合成/原生向量 |
| 本地身份、服务端身份与刷新 | [本地a7/a8](../archive/LOCAL_ID_RESEARCH.md)、[注册阶段](../archive/root/REGISTRATION_ID_STAGES.md)、[ntp](../archive/NTP_RESPONSE.md)、[当前a7刷新](A7_REFRESH_20261003.md) | `local_identity.py`、`registration_state.py`、`fingerprint_refresh.py` |
| 信封、collector路由与m320 | [SDK信封](../archive/ENVELOPE_SDK.md)、[m320](../archive/REGISTRATION_CHECKSUM.md) | `verify_registration_collectors.py`、`verify_registration_m320.py` |
| 注册、配置和区域依赖 | [注册流](../archive/REGISTRATION_FLOW.md)、[依赖审计](../archive/REGISTRATION_CONFIG_DEPENDENCIES.md)、[newreg](../archive/NEWREG_SIGNATURE.md)、[scfg](../archive/SCFG_SOURCE.md)、[regionPath](../archive/REGION_PATH.md)、[选区静态链](../archive/REGION_SELECTION_STATIC.md) | `registration_*`、`newreg.py`、`scfg.py`、`region_state.py` |
| 登录输入来源和状态传递 | [登录链](../archive/root/LOGIN_PROTOCOL.md)、[静态恢复](../archive/LOGIN_PROTOCOL_STATIC.md)、[公共上下文](../archive/LOGIN_CONTEXT.md)、[B指纹](../archive/LOGIN_FINGERPRINT_FIELDS.md)、[注册后状态清单](../archive/REGISTRATION_LOGIN_CONTEXT.md) | `login_protocol.py`、`login_context.py`、`inspect_login_static.py` |
| 成功原生包证明了什么 | [完整抓包结论](../archive/FULL_REGISTRATION_LOGIN_CAPTURE.md)、[设备身份链](../archive/FULL_CAPTURE_DEVICE_CHAIN.md)、[登录链](../archive/FULL_CAPTURE_LOGIN_CHAIN.md)、[Incognia生成链](../archive/INCOGNIA_GENERATION_TRACE.md) | 历史证据与纯协议实现边界分开；不迁移原始抓包 |

## 已修正的历史结论

归档中的“当前”“未实现”是当时的记录。尤其注意：

- 早期 `a2 563/566` 与大 bio 正文差异，后来定位到签名只取 Body UTF-8 前 16,200 字节；当前支持布局为 566/566，另有 4 条 `x0=4` 不在支持范围。见当前字段状态及原生研究；不能沿用早期差异作为当前结果。
- `a10` 第二段是 SDK 启动随机值，不是逐请求计数；`b2`、`b17`、`b18` 是不同计数分支。旧字段总表用于查采集位置，不覆盖 [后续原生对照](B_COUNTERS_RENDER_20261002.md)。
- provider 旧隔离实验的 `parameter=1` 不代表真实 legacy 配置；后来已观测原生 `a3=25` 与配套 salt。`default/legacy` 是经过对拍的参数组合，不可只改数字。
- 旧登录审计写 Incognia 尚无本地生成，之后已有 [生成链与离线对拍](../archive/INCOGNIA_GENERATION_TRACE.md)。这不代表可以生成任意有效安装身份，也不证明新的登录请求会成功。
- 旧 `a9_provider_emulate.py` 仍是探索工具，配置解析可能在未支持的 `___dynamic_cast` 停止。真实 provider 配置对拍来自后续原生观察，不能把该探索器当作完整恢复实现。

## 离线工具复跑

从项目根目录操作。a2/a9抓包复核只需运行依赖；原生静态分析/Unicorn工具使用独立环境：

```sh
python3 -m venv .private/research-venv
.private/research-venv/bin/python -m pip install -r requirements.lock -r requirements-research.txt
```

以下 `python` 指该环境解释器。输入始终只读；工具不发网络请求、不连接手机。真实材料和派生报告放 `.private/`，不要提交。已有输出文件/目录会拒绝覆盖，复跑换新输出路径。

```sh
# Charles JSON数组，或含mtgsig和msg_hex的单样本；body须为明确UTF-8 text。
# 完整16字节对拍；独立从a5.b2取sequence，不从预期a2倒推。
python tools/verify_a2_pass2.py .private/capture.json

# a9支持直接签名对象、{"mtgsig": ...}或Charles JSON数组。
# 必须指定a9的profile；a5的profile不能替代它。
python tools/a9_validate_captures.py .private/capture.json \
  --profile default --out .private/a9-review.json

# 使用与研究记录匹配的旧Mach-O；不随仓库发布，不自动搜索其他文件。
python tools/a9_native_verify.py --image /path/to/Keeta.dec \
  --cases 3 --out .private/native-a9-review.json
python tools/verify_registration_collectors.py --image /path/to/Keeta.dec \
  --out .private/collector-review.json
python tools/verify_registration_m320.py --image /path/to/Keeta.dec \
  --out-dir .private/m320-review

# 只生成反汇编/元数据。out是尚不存在的目录。
python tools/a9_unflatten.py 0x30c408 --image /path/to/Keeta.dec \
  --out .private/provider-listing
python tools/inspect_login_static.py --image /path/to/Keeta.dec \
  --out .private/login-static

# 探索入口，未支持导入会报错；不是日常签名或验收前置步骤。
python tools/a9_provider_emulate.py --image /path/to/Keeta.dec \
  --parser-only --out .private/provider-exploration.json
```

`verify_registration_m320.py` 默认仅用合成对象，输出到新目录，**不覆盖** `tests/fixtures/`。可选 `--evidence-dir` 显式指定历史 `current_registration_context_02.json`、`current_registration_payloads_01.json`、`current_reporting_context_04.json` 所在目录；没有提供就不读取任何私有抓包上下文。可选真实证据未随本轮合成对拍重跑。

原生 VM 工具的固定 RVA 对应历史镜像 SHA-256：
`0900cac89f75fc4f75279c708785bf2c7a03c228301a8e75ce62f93e3ad88488`。
工具在映射前校验哈希，其他镜像拒绝运行。这与当前设备镜像不是同一个版本的通用承诺；更新版本先重新定位并验证，不能直接沿用旧偏移。静态listing工具可读显式输入，但旧dispatcher模式与ObjC解析能力仍有限，hash会写入输出。

a9复核输出计数、模式、长度及校验结果，不输出明文和身份；它验证同一密文可精确重编码，不替代原生核心对拍。原旧脚本写死的provider/UUID/builder证据不再默认读取，也没有算作本轮已验证；此处只报告实际执行范围。新配置可用 `mtgsig.a9_cli` 的显式参数诊断，未知配置不能用命名profile猜补。

## 未搬入的内容

- 抓包、账号/邮箱凭据、私有密钥、实际代理授权、Mach-O/dump、运行账本及交付结果。
- 一次性设备改写脚本、旧容量/费用模型、重复部署说明、被推翻的计数启发式、与本协议无关的skill/prompt资料。
- 历史的固定索引审计脚本和过时中间结果，仍可从 [旧提交](https://github.com/xiaozeng2296/keeta-device/tree/6197c52899b5bfcbed858004f064d7cd3c1eeea1) 查阅；本轮保留其文档中的来源索引，不把私有文件路径伪装成新项目开箱可运行命令。
