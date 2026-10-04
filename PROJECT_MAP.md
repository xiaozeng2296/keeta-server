# 项目文件与服务边界

本仓库是独立代码副本，不读取旧工程源码。首次整理来自已验证运行代码，未继承旧 Git 历史。

| 目录/入口 | 保留理由 |
|---|---|
| `farm/` | Web、账号状态、统一任务队列/本机响应文件、导出、签名器、a7维护、代理适配与通用批次入口 |
| `mtgsig/` + `keeta_a2.py` | 协议密码、原生状态模型与必需算法表 |
| `keeta_rpc.py` + `rpc/` | 签名/加解密 HTTP 服务、发布包、验证与回滚 |
| `keeta_login.py` / `keeta_offline_flow.py` / `mailbox.py` | 已有RPC兼容能力的实际依赖；不是主采集前置步骤 |
| `keeta_client.py` / `keeta_sign_rpc.js` | 可选真机对拍兼容，普通采集无需启用 |
| `config/` + `deploy/` + `scripts/` | 无凭据模板、进程入口、测试与提交检查 |
| `tools/` | 日常检查、原生观测、离线对拍、代理桥接及现用数据映射 |
| `tests/` | 当前能力的合成回归与显式可选集成验证 |
| `docs/` | 当前流程、架构建议、协议更新、字段来源与算法研究笔记 |

`.private/`、`exports/`、抓包、dump、历史临时实验和旧文档全集留在运行数据区或旧研究仓库，不加入新项目。

本次逆向分支补迁详见 [离线研究指南](docs/research/OFFLINE_RESEARCH.md) 和 [来源清单](docs/research/PROTOCOL_MIGRATION_MANIFEST.json)。研究依赖单独放在 `requirements-research.txt`。

下列是本次整理的完整文件清单（后续新增以 Git 为准）：

## 根目录

```text
.gitignore
PROJECT_MAP.md
README.md
keeta_a2.py
keeta_client.py
keeta_login.py
keeta_offline_flow.py
keeta_rpc.py
keeta_sign_offline.py
keeta_sign_rpc.js
mailbox.py
requirements-dev.txt
requirements-native.txt
requirements-research.txt
requirements.lock
requirements.txt
启动面板.command
```

## config

```text
config/clash-pool-setting.example.json
config/clash-pool.example.yaml
config/mysql.example.json
config/proxy-chain.example.json
config/routes.example.json
config/rpc-deploy.example.json
config/shops.example.json
```

## deploy

```text
deploy/keeta-proxy.service
deploy/keeta-rpc.service
deploy/keeta-web.service
deploy/keeta-worker.service
```

## docs

```text
docs/ACCOUNT_CHECKS.md
docs/ARCHITECTURE.md
docs/COLLECTION_FLOW.md
docs/MIGRATION.md
docs/MTGSIG_FIELDS_STATUS.md
docs/OPERATIONS.md
docs/PROTOCOL.md
docs/PROTOCOL_UPDATE.md
docs/README.md
docs/TESTING.md
docs/VERSION_CONTROL.md
docs/archive/A2_PASS2.md
docs/archive/A5_B13_AUDIT.md
docs/archive/A9_OLD_SAMPLE_FINDINGS.md
docs/archive/A9_PROVIDER_NOTES.md
docs/archive/A9_RPC.md
docs/archive/A9_USAGE.md
docs/archive/CORPSE_CODEC.md
docs/archive/ENVELOPE_SDK.md
docs/archive/FULL_CAPTURE_DEVICE_CHAIN.md
docs/archive/FULL_CAPTURE_LOGIN_CHAIN.md
docs/archive/FULL_REGISTRATION_LOGIN_CAPTURE.md
docs/archive/INCOGNIA_GENERATION_TRACE.md
docs/archive/LOCAL_ID_RESEARCH.md
docs/archive/LOGIN_CONTEXT.md
docs/archive/LOGIN_FINGERPRINT_FIELDS.md
docs/archive/LOGIN_PROTOCOL_STATIC.md
docs/archive/M175_SOURCE.md
docs/archive/M239_SOURCE.md
docs/archive/M324_SOURCE.md
docs/archive/NEWREG_SIGNATURE.md
docs/archive/NTP_RESPONSE.md
docs/archive/README.md
docs/archive/REGION_PATH.md
docs/archive/REGION_SELECTION_STATIC.md
docs/archive/REGISTRATION_CHECKSUM.md
docs/archive/REGISTRATION_CONFIG_DEPENDENCIES.md
docs/archive/REGISTRATION_FLOW.md
docs/archive/REGISTRATION_LOGIN_CONTEXT.md
docs/archive/SCFG_SOURCE.md
docs/archive/root/DEVICE_FINGERPRINT_FIELDS.md
docs/archive/root/FINGERPRINT.md
docs/archive/root/LOGIN_PROTOCOL.md
docs/archive/root/REGISTRATION_ID_STAGES.md
docs/archive/root/V5_SIGN_FIELDS.md
docs/research/A7_REFRESH_20261003.md
docs/research/B16_DEVICEINFO_COUNT_20261002.md
docs/research/B_COUNTERS_RENDER_20261002.md
docs/research/DYNAMIC_STATE_AUDIT_20261003.md
docs/research/FIELD_LIFECYCLE_CONTROLS_20261003.md
docs/research/FIELD_STATUS_HISTORY_20261004.md
docs/research/NATIVE_FIELDS_20261001.md
docs/research/OFFLINE_RESEARCH.md
docs/research/PROTOCOL_MIGRATION_MANIFEST.json
docs/research/PROTOCOL_OBSERVATIONS_20261001.json
docs/research/README.md
```

## farm

```text
farm/__init__.py
farm/_paths.py
farm/account_checks.py
farm/account_controls.py
farm/account_profiles.py
farm/batch_audit.py
farm/batch_prepare.py
farm/batch_report.py
farm/charles.py
farm/env.py
farm/executor.py
farm/fingerprint_maintenance.py
farm/fingerprint_refresh.py
farm/fullsign.py
farm/local_files.py
farm/response_files.py
farm/mysql_admin.py
farm/mysql_cli.py
farm/mysql_export.py
farm/mysql_import.py
farm/mysql_requirements.txt
farm/mysql_schema.sql
farm/mysql_selection.py
farm/mysql_service.py
farm/mysql_store.py
farm/mysql_worker.py
farm/panel.py
farm/proxy.py
farm/proxy_service.py
farm/recommendations.py
farm/registry.py
farm/request_context.py
farm/request_freshness.py
farm/request_templates.py
farm/static/favicon.svg
farm/static/panel.css
farm/static/panel.js
farm/tasks.py
farm/templates/panel.html
farm/worker.py
```

## mtgsig

```text
mtgsig/a9_cli.py
mtgsig/a9_codec.py
mtgsig/a9_legacy_profile.json
mtgsig/bootstrap_identity.py
mtgsig/collection_cache.py
mtgsig/corpse_codec.py
mtgsig/data/T.bin
mtgsig/data/tableA.bin
mtgsig/data/tableB_const.bin
mtgsig/email_flow.py
mtgsig/embedded_rsa_pubkeys.json
mtgsig/envelope_codec.py
mtgsig/fingerprint_refresh.py
mtgsig/http_transport.py
mtgsig/incognia_state.py
mtgsig/incognia_token.py
mtgsig/keeta_const.json
mtgsig/local_identity.py
mtgsig/login_context.py
mtgsig/login_protocol.py
mtgsig/m175_codec.py
mtgsig/mail_transport.py
mtgsig/mtg_crypto.py
mtgsig/newreg.py
mtgsig/ntp_protocol.py
mtgsig/oneid.py
mtgsig/provider_config.py
mtgsig/ref_domestic/M.bin
mtgsig/region_state.py
mtgsig/registration_checksum.py
mtgsig/registration_collector.py
mtgsig/registration_payloads.py
mtgsig/registration_region.py
mtgsig/registration_reporting.py
mtgsig/registration_state.py
mtgsig/request_trace.py
mtgsig/scfg.py
mtgsig/session_identity.py
mtgsig/timestamp_identity.py
```

## rpc

```text
rpc/DEPLOYMENT_DEPENDENCIES.md
rpc/README.md
rpc/deploy.py
rpc/remote_update.py
rpc/requirements.txt
rpc/smoke.py
```

## scripts

```text
scripts/check_account_apis.sh
scripts/check_account_signatures.sh
scripts/check_proxy.sh
scripts/check_staged.py
scripts/python.sh
scripts/smoke_services.py
scripts/start_panel.sh
scripts/start_proxy.sh
scripts/start_rpc.sh
scripts/start_worker.sh
scripts/verify_repository.py
```

## tests

```text
tests/__init__.py
tests/fixtures/a2_pass2_accepted_boundaries.json
tests/fixtures/a2_pass2_synthetic.json
tests/fixtures/a9_native_cbc_vectors.json
tests/fixtures/a9_native_vectors.json
tests/fixtures/corpse_native_vectors.json
tests/fixtures/envelope_rsa_vector.json
tests/fixtures/fingerprint_i_series_vector.json
tests/fixtures/m175_vectors.json
tests/fixtures/m239_synthetic.json
tests/fixtures/m324_native_vectors.json
tests/fixtures/oneid_native_vector.json
tests/fixtures/registration_m320_pairs_vectors.json
tests/fixtures/registration_m320_vectors.json
tests/test_a2_message.py
tests/test_a9_cli.py
tests/test_a9_rpc.py
tests/test_account_check.py
tests/test_account_checks.py
tests/test_account_profiles.py
tests/test_bootstrap_identity.py
tests/test_collection_refresh.py
tests/test_corpse_codec.py
tests/test_crawl_request_context.py
tests/test_email_flow.py
tests/test_envelope_codec.py
tests/test_envelope_rpc.py
tests/test_envelope_sdk.py
tests/test_farm_menu_failure.py
tests/test_fingerprint_refresh.py
tests/test_full_crawl_products.py
tests/test_fullsign.py
tests/test_http_transport.py
tests/test_incognia_state.py
tests/test_incognia_token.py
tests/test_local_identity.py
tests/test_login_context.py
tests/test_login_execution.py
tests/test_login_protocol.py
tests/test_m175_codec.py
tests/test_mail_transport.py
tests/test_mailbox.py
tests/test_mysql_admin.py
tests/test_mysql_farm.py
tests/test_mysql_integration.py
tests/test_local_response_files.py
tests/test_newreg_signature.py
tests/test_ntp_flow.py
tests/test_ntp_protocol.py
tests/test_offline_flow.py
tests/test_oneid.py
tests/test_panel.py
tests/test_protocol_lifecycle.py
tests/test_protocol_probe.js
tests/test_protocol_watch.py
tests/test_provider_config.py
tests/test_proxy.py
tests/test_proxy_chain_bridge.py
tests/test_region_state.py
tests/test_registration_checksum.py
tests/test_registration_execution.py
tests/test_registration_payloads.py
tests/test_registration_reporting.py
tests/test_registration_state.py
tests/test_remote_update.py
tests/test_request_freshness.py
tests/test_research_tools.py
tests/test_rpc_deploy.py
tests/test_rpc_smoke.py
tests/test_scfg.py
tests/test_session_identity.py
tests/test_signing_counters.py
tests/test_signing_profiles.py
tests/test_timestamp_identity.py
```

## tools

```text
tools/README.md
tools/a9_native_verify.py
tools/a9_provider_emulate.py
tools/a9_unflatten.py
tools/a9_validate_captures.py
tools/check_account.py
tools/crawl_keeta.py
tools/inspect_login_static.py
tools/protocol_lifecycle.js
tools/protocol_probe.js
tools/protocol_trace.js
tools/protocol_watch.py
tools/proxy_chain_bridge.py
tools/refresh_fingerprint.py
tools/verify_a2_pass2.py
tools/verify_registration_collectors.py
tools/verify_registration_m320.py
```
