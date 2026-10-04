"""把项目根与 tools/ 加入 sys.path，供复用 crawl_keeta / keeta_client / keeta_sign_offline。

导入本模块即生效（幂等）。ProcessPool spawn 的子进程里也会重新导入。
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (ROOT, os.path.join(ROOT, "tools")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
