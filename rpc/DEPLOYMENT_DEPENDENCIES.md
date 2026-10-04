# RPC 发布依赖

初装依赖 `rpc/requirements.txt`；整套项目统一用根 `requirements.txt`。运行闭包和验收清单在 `remote_update.RUNTIME_FILES` / `OPTIONAL_FILES`。构建时每项必须存在；测试在解出的独立目录执行。

共享密码资源：`T.bin`、`tableA.bin`、`tableB_const.bin`、`ref_domestic/M.bin`、`keeta_const.json`、`a9_legacy_profile.json`、`embedded_rsa_pubkeys.json`。它们是算法表/已知配置/公钥，不是账号私钥。

`tests/test_rpc_deploy.py` 验证包的哈希、路径、模块导入和配置模板；`scripts/smoke_services.py` 用本地 HTTP 核验签名服务。当前远端机器是否已安装某一提交，必须由实际部署记录确认，Git 推送本身不代表服务更新。
