# 工具入口

- `check_account.py`：单材料离线检查；多账号活动会话检查用 `farm.account_checks`。
- `refresh_fingerprint.py`：a7材料预检与显式维护配置/上报，参数以 `--help` 为准。
- `protocol_watch.py` / `protocol_probe.js` / `protocol_lifecycle.js` / `protocol_trace.js`：可选原生对拍与生命周期观测，依赖设备及匹配版本 Frida。
- `proxy_chain_bridge.py`：GOST 3的私有链式配置与进程包装。
- `crawl_keeta.py`：现有店铺/商品/子菜字段映射与旧采集兼容入口。正式大批次走 `farm.batch_*`。兼容真机模式用 `keeta_client.py` / `keeta_sign_rpc.js`，模板由 `KEETA_CAPTURE` 指向私有抓包，SSH由 `KEETA_DEVICE_SSH_TARGET` 指向已配置Host；不内置设备密码。

推荐发现、批次准备、运行监督、计时、验收已经进入 `farm/`，不再依赖带日期的 `.private` 脚本。通用离线研究工具已补迁；未选用的一次性旧实验仍在原研究仓库。

离线研究：`verify_a2_pass2.py`、`a9_validate_captures.py`、`a9_native_verify.py`、`a9_provider_emulate.py`、`a9_unflatten.py`、`verify_registration_collectors.py`、`verify_registration_m320.py`、`inspect_login_static.py`。输入/输出必须显式指定，具体范围与历史限制见 [研究指南](../docs/research/OFFLINE_RESEARCH.md)。
