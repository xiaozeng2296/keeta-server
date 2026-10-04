# 工具入口

- `check_account.py`：单材料离线检查；多账号活动会话检查用 `farm.account_checks`。
- `refresh_fingerprint.py`：a7材料预检与显式维护配置/上报，参数以 `--help` 为准。
- `protocol_watch.py` / `protocol_probe.js` / `protocol_lifecycle.js` / `protocol_trace.js`：可选原生对拍与生命周期观测，依赖设备及匹配版本 Frida。
- `proxy_chain_bridge.py`：GOST 3的私有链式配置与进程包装。
- `crawl_keeta.py`：现有店铺/商品/子菜字段映射与旧采集兼容入口。正式大批次走 `farm.batch_*`。兼容真机模式用 `keeta_client.py` / `keeta_sign_rpc.js`，模板由 `KEETA_CAPTURE` 指向私有抓包，SSH由 `KEETA_DEVICE_SSH_TARGET` 指向已配置Host；不内置设备密码。

推荐发现、批次准备、运行监督、计时、验收已经进入 `farm/`，不再依赖带日期的 `.private` 脚本。旧实验代码只在原研究仓库维护。
