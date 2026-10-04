# 项目文件与服务边界

本仓库是独立代码副本，不读取旧工程源码。首次整理来自已验证运行代码，未继承旧 Git 历史。

| 目录/入口 | 保留理由 |
|---|---|
| `farm/` | Web、账号状态、数据库/本地队列、导出、签名器、a7维护、代理适配与通用批次入口 |
| `mtgsig/` + `keeta_a2.py` | 协议密码、原生状态模型与必需算法表 |
| `keeta_rpc.py` + `rpc/` | 签名/加解密 HTTP 服务、发布包、验证与回滚 |
| `keeta_login.py` / `keeta_offline_flow.py` / `mailbox.py` | 已有RPC兼容能力的实际依赖；不是主采集前置步骤 |
| `keeta_client.py` / `keeta_sign_rpc.js` | 可选真机对拍兼容，普通采集无需启用 |
| `config/` + `deploy/` + `scripts/` | 无凭据模板、进程入口、测试与提交检查 |
| `tools/` | 日常检查、原生观测、代理桥接及现用数据映射 |
| `tests/` | 当前能力的合成回归与显式可选集成验证 |
| `docs/` | 当前流程、架构建议、协议更新、研究证据与少量算法笔记 |

`.private/`、`exports/`、抓包、dump、历史临时实验和旧文档全集留在运行数据区或旧研究仓库，不加入新项目。

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
docs/MTGSIG_FIELDS_STATUS.md
docs/MIGRATION.md
docs/OPERATIONS.md
docs/PROTOCOL.md
docs/PROTOCOL_UPDATE.md
docs/README.md
docs/TESTING.md
docs/VERSION_CONTROL.md
docs/archive/A2_PASS2.md
docs/archive/A9_RPC.md
docs/archive/A9_USAGE.md
docs/archive/ENVELOPE_SDK.md
docs/archive/README.md
docs/archive/root/DEVICE_FINGERPRINT_FIELDS.md
docs/archive/root/FINGERPRINT.md
docs/research/A7_REFRESH_20261003.md
docs/research/B16_DEVICEINFO_COUNT_20261002.md
docs/research/B_COUNTERS_RENDER_20261002.md
docs/research/DYNAMIC_STATE_AUDIT_20261003.md
docs/research/FIELD_LIFECYCLE_CONTROLS_20261003.md
docs/research/FIELD_STATUS_HISTORY_20261004.md
docs/research/NATIVE_FIELDS_20261001.md
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
farm/batch_run.py
farm/batch_watch.py
farm/charles.py
farm/env.py
farm/executor.py
farm/fingerprint_maintenance.py
farm/fingerprint_refresh.py
farm/fullsign.py
farm/local_batch.py
farm/local_ledger.py
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
scripts/set_local_proxy.sh
scripts/smoke_services.py
scripts/start_batch.sh
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
tests/test_account_recovery.py
tests/test_batch_workflow.py
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
tests/test_local_batch.py
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
tools/check_account.py
tools/crawl_keeta.py
tools/protocol_lifecycle.js
tools/protocol_probe.js
tools/protocol_trace.js
tools/protocol_watch.py
tools/proxy_chain_bridge.py
tools/refresh_fingerprint.py
```
