# 提交与发布

新仓库使用普通 Git 索引和 `main`，不再用旧工程的独立暂存区 / 发布分支。

```bash
git status --short
git add <明确修改的源码与文档>
python scripts/check_staged.py --all
git diff --cached --stat
git commit -m "概括实际变化"
git push origin main
```

推送前完成 [测试要求](TESTING.md)。账号、真实配置、密钥、抓包、SQLite 和导出结果保持在忽略的运行目录；新增源码在普通 Git status 可见，不自动隐藏在巨大白名单中。凭据检查不能替代人工审查。

旧仓库历史和研究暂存内容未并入本仓库；研究材料需追溯时查旧 `keeta-device` / `codex/keeta-project`。远端 RPC 更新用 `rpc/deploy.py`，Git push 不会自动重启本地或远端服务。
